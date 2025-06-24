#!/usr/bin/python3
import time
import paho.mqtt.client as mqtt
import yaml
import alsaaudio
import signal
import sys
import json
import select
import logging
import logging.handlers # Make sure this is imported for SysLogHandler
from typing import Dict, Any, Optional, List

# Configuration
DEFAULT_VOLUME = 80
DEFAULT_PUBLISH_INTERVAL = 5  # seconds
shutdown_flag = False

# Global logger instance - Initialize with a basic console handler immediately
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Default level for console logging
# Create a console handler for early logging (e.g., config loading errors)
console_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class VolumeControl:
    def __init__(self, device_id: str, config: Dict[str, Any], mqtt_client: mqtt.Client):
        self.id = device_id
        self.config = config
        self.mqttc = mqtt_client
        mqtt_conf = config['mqtt']
        self.base_topic = f"{mqtt_conf['prefix']}{mqtt_conf['device_prefix']}/{mqtt_conf['id']}"
        self.volume_topic = f"{self.base_topic}/volume"
        self.mute_topic = f"{self.base_topic}/mute"
        self.publish_interval = mqtt_conf.get('publish_interval', DEFAULT_PUBLISH_INTERVAL)
        self.periodic_publish_enabled = self.publish_interval > 0
        self.last_publish_time = 0
        
        # Initialize mixer and event handling
        self.mixer = self._get_mixer()
        # Check if mixer is None (in case _get_mixer had a critical failure and exited)
        if self.mixer is None:
            # This path should ideally be unreachable if _get_mixer exits on critical error,
            # but good for type checking or if that exit logic changes.
            raise RuntimeError(f"[{self.id}] Failed to initialize ALSA mixer.")

        self.mixer_poll = select.poll()
        mixer_fd = self.mixer.polldescriptors()[0][0]
        self.mixer_poll.register(mixer_fd, select.POLLIN)
        
        # Initialize state
        self.volume = self.volume_get()
        self.mute_state = self.mute_get()
        if 'default_volume' in config['devices'][device_id]:
            default_vol = config['devices'][device_id]['default_volume']
            logger.info(f"[{self.id}] Setting initial volume to default: {default_vol}%")
            self.volume_set(default_vol)

    def _get_mixer(self) -> Optional[alsaaudio.Mixer]: # Changed return type to Optional
        card_number = self.config['devices'][self.id]['alsa_number']
        control_name = self.config['devices'][self.id].get('control_name', 'Master')
        
        try:
            mixer_obj = alsaaudio.Mixer(control_name, 0, card_number)
            logger.info(f"[{self.id}] Successfully initialized ALSA mixer '{control_name}' on card {card_number}.")
            return mixer_obj
        except alsaaudio.ALSAAudioError as e:
            logger.warning(f"[{self.id}] Failed to get mixer for '{control_name}' on card {card_number}: {e}. Trying 'Master' instead...", exc_info=True)
            try:
                mixer_obj = alsaaudio.Mixer('Master', 0, card_number)
                logger.info(f"[{self.id}] Successfully initialized ALSA mixer 'Master' on card {card_number} as fallback.")
                return mixer_obj
            except alsaaudio.ALSAAudioError as e_master:
                logger.critical(f"[{self.id}] Failed to get mixer 'Master' on card {card_number} as fallback: {e_master}. ALSA control unavailable. Exiting.", exc_info=True)
                sys.exit(1) # Critical error, cannot proceed without mixer
        return None # Should not be reached if sys.exit() is called, but for type consistency

    def check_for_changes(self) -> bool:
        """Check for ALSA mixer events and handle them if any occurred"""
        events = self.mixer_poll.poll(0)  # Non-blocking poll
        if events:
            self.mixer.handleevents()
            new_volume = self.volume_get()
            new_mute = self.mute_get()
            
            changed = False
            if new_volume != self.volume:
                logger.info(f"[{self.id}] ALSA volume changed from {self.volume}% to {new_volume}%.")
                self.volume = new_volume
                self._mqtt_publish(f"{self.volume_topic}/state", new_volume)
                changed = True
                
            if new_mute != self.mute_state:
                logger.info(f"[{self.id}] ALSA mute state changed from {'ON' if self.mute_state else 'OFF'} to {'ON' if new_mute else 'OFF'}.")
                self.mute_state = new_mute
                self._mqtt_publish(f"{self.mute_topic}/state", "ON" if new_mute else "OFF")
                changed = True
                
            if changed:
                self.last_publish_time = time.time()
                return True
        return False

    def publish_current_state(self) -> None:
        if not self.periodic_publish_enabled or shutdown_flag:
            return
            
        current_time = time.time()
        if current_time - self.last_publish_time >= self.publish_interval:
            current_volume = self.volume_get()
            current_mute = self.mute_get()
            logger.debug(f"[{self.id}] Periodically publishing current state: Vol={current_volume}%, Mute={'ON' if current_mute else 'OFF'}.")
            self._mqtt_publish(f"{self.volume_topic}/state", current_volume)
            self._mqtt_publish(f"{self.mute_topic}/state", "ON" if current_mute else "OFF")
            self.last_publish_time = current_time
    
    def volume_get(self) -> int:
        try:
            return int(self.mixer.getvolume()[0])
        except alsaaudio.ALSAAudioError as e:
            logger.error(f"[{self.id}] Failed to get volume: {e}. Reinitializing mixer...", exc_info=True)
            self.mixer = self._get_mixer()
            if self.mixer is None: # Handle case where reinitialization also fails critically
                logger.critical(f"[{self.id}] Critical: Mixer reinitialization failed after volume_get error. Cannot retrieve volume.")
                return 0 # Return a safe default or raise error
            return int(self.mixer.getvolume()[0])
        
    def mute_get(self) -> bool:
        try:
            return bool(self.mixer.getmute()[0])
        except alsaaudio.ALSAAudioError as e:
            logger.error(f"[{self.id}] Failed to get mute state: {e}. Reinitializing mixer...", exc_info=True)
            self.mixer = self._get_mixer()
            if self.mixer is None: # Handle case where reinitialization also fails critically
                logger.critical(f"[{self.id}] Critical: Mixer reinitialization failed after mute_get error. Cannot retrieve mute state.")
                return False # Return a safe default or raise error
            return bool(self.mixer.getmute()[0])

    def volume_set(self, volume: int) -> None:
        # Debugging info to track commanded vs actual
        commanded_volume = volume
        previous_volume = self.volume_get() # Get actual current ALSA volume before commanding change

        self.volume = commanded_volume # Update internal state immediately based on command
        
        try:
            logger.info(f"[{self.id}] MQTT commanded volume change from {previous_volume}% to {commanded_volume}%. Attempting ALSA set...")
            self.mixer.setvolume(commanded_volume)
            # Read back immediately to verify what ALSA reports
            actual_alsa_volume = self.volume_get()
            logger.info(f"[{self.id}] ALSA set command sent for {commanded_volume}%. ALSA now reports {actual_alsa_volume}%.")

            if actual_alsa_volume != commanded_volume:
                logger.warning(f"[{self.id}] Discrepancy: ALSA reports {actual_alsa_volume}% after commanding {commanded_volume}%.")
                self.volume = actual_alsa_volume # Update internal state to match ALSA's reality
                self._mqtt_publish(f"{self.volume_topic}/state", actual_alsa_volume) # Publish actual
            else:
                self._mqtt_publish(f"{self.volume_topic}/state", commanded_volume) # Publish commanded (matches actual)

        except alsaaudio.ALSAAudioError as e:
            logger.error(f"[{self.id}] Failed to set volume to {commanded_volume}% (first attempt): {e}. Reinitializing mixer and retrying...", exc_info=True)
            try:
                self.mixer = self._get_mixer()
                if self.mixer is None: # Handle case where reinitialization also fails critically
                    logger.critical(f"[{self.id}] Critical: Mixer reinitialization failed after volume_set error. Cannot set volume.")
                    current_alsa_volume = self.volume_get() # Try to get current even if mixer is none, might still work for a sec
                    self.volume = current_alsa_volume
                    self._mqtt_publish(f"{self.volume_topic}/state", current_alsa_volume)
                    return
                self.mixer.setvolume(commanded_volume) # Retry
                actual_alsa_volume_after_retry = self.volume_get()
                logger.info(f"[{self.id}] After reinit and retry for {commanded_volume}%, ALSA reports {actual_alsa_volume_after_retry}%.")
                if actual_alsa_volume_after_retry != commanded_volume:
                    logger.warning(f"[{self.id}] Discrepancy after retry: ALSA reports {actual_alsa_volume_after_retry}% after commanding {commanded_volume}%.")
                    self.volume = actual_alsa_volume_after_retry
                    self._mqtt_publish(f"{self.volume_topic}/state", actual_alsa_volume_after_retry)
                else:
                    self._mqtt_publish(f"{self.volume_topic}/state", commanded_volume)
            except alsaaudio.ALSAAudioError as e2:
                logger.critical(f"[{self.id}] CRITICAL: Failed to set volume to {commanded_volume}% even after reinitialization and retry: {e2}. Volume might be incorrect.", exc_info=True)
                # If even retry fails, publish what ALSA currently reports (could be unchanged)
                current_alsa_volume = self.volume_get()
                self.volume = current_alsa_volume
                self._mqtt_publish(f"{self.volume_topic}/state", current_alsa_volume)
            
        self.last_publish_time = time.time()

    def mute_set(self, state: bool) -> None:
        commanded_state = 1 if state else 0
        previous_state = self.mute_get()

        try:
            logger.info(f"[{self.id}] MQTT commanded mute change from {'ON' if previous_state else 'OFF'} to {'ON' if state else 'OFF'}. Attempting ALSA set...")
            self.mixer.setmute(commanded_state)
            actual_alsa_state = self.mute_get()
            logger.info(f"[{self.id}] ALSA set mute command sent for {'ON' if state else 'OFF'}. ALSA now reports {'ON' if actual_alsa_state else 'OFF'}.")

            if actual_alsa_state != state:
                logger.warning(f"[{self.id}] Discrepancy: ALSA reports {'ON' if actual_alsa_state else 'OFF'} after commanding {'ON' if state else 'OFF'}.")
            
        except alsaaudio.ALSAAudioError as e:
            logger.error(f"[{self.id}] Failed to set mute to {'ON' if state else 'OFF'} (first attempt): {e}. Reinitializing mixer and retrying...", exc_info=True)
            try:
                self.mixer = self._get_mixer()
                if self.mixer is None:
                    logger.critical(f"[{self.id}] Critical: Mixer reinitialization failed after mute_set error. Cannot set mute.")
                    current_alsa_state = self.mute_get()
                    self.mute_state = current_alsa_state
                    self._mqtt_publish(f"{self.mute_topic}/state", "ON" if current_alsa_state else "OFF")
                    return
                self.mixer.setmute(commanded_state)
                actual_alsa_state_after_retry = self.mute_get()
                logger.info(f"[{self.id}] After reinit and retry for {'ON' if state else 'OFF'}, ALSA reports {'ON' if actual_alsa_state_after_retry else 'OFF'}.")
                if actual_alsa_state_after_retry != state:
                    logger.warning(f"[{self.id}] Discrepancy after retry: ALSA reports {'ON' if actual_alsa_state_after_retry else 'OFF'} after commanding {'ON' if state else 'OFF'}.")
            except alsaaudio.ALSAAudioError as e2:
                logger.critical(f"[{self.id}] CRITICAL: Failed to set mute to {'ON' if state else 'OFF'} even after reinitialization and retry: {e2}. Mute state might be incorrect.", exc_info=True)
                
        self.mute_state = self.mute_get() # Ensure internal state reflects ALSA's reality after all attempts
        self._mqtt_publish(f"{self.mute_topic}/state", "ON" if self.mute_state else "OFF") # Publish final actual state
        self.last_publish_time = time.time()

    def _mqtt_publish(self, topic: str, payload, retain: bool = True) -> None:
        """Wrapper for MQTT publish with version compatibility"""
        try:
            if hasattr(self.mqttc, 'publish') and callable(self.mqttc.publish):
                self.mqttc.publish(topic, payload, retain=retain)
                logger.debug(f"[{self.id}] MQTT Published: Topic='{topic}', Payload='{payload}', Retain={retain}")
        except Exception as e:
            logger.error(f"[{self.id}] Failed to publish MQTT message to topic '{topic}': {e}", exc_info=True)

    def volume_up(self) -> None:
        new_volume = min(self.volume + 1, 100)
        logger.info(f"[{self.id}] Volume UP command. Setting to {new_volume}%.")
        self.volume_set(new_volume)

    def volume_down(self) -> None:
        new_volume = max(self.volume - 1, 1)
        logger.info(f"[{self.id}] Volume DOWN command. Setting to {new_volume}%.")
        self.volume_set(new_volume)

def signal_handler(sig, frame):
    global shutdown_flag
    logger.info(f"Received shutdown signal ({sig}), cleaning up...")
    shutdown_flag = True

def load_config() -> Dict[str, Any]:
    try:
        with open('configuration.yaml', 'r') as config_file:
            config_data = yaml.safe_load(config_file)
            logger.info("Configuration loaded successfully.") # This will now work
            return config_data
    except FileNotFoundError:
        logger.critical("Configuration file 'configuration.yaml' not found. Exiting.", exc_info=True)
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.critical(f"Error parsing configuration YAML: {e}. Exiting.", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unexpected error loading configuration: {e}. Exiting.", exc_info=True)
        sys.exit(1)

def on_connect_v3(client: mqtt.Client, userdata, flags, rc):
    """MQTT v3.1.1 connection callback"""
    if rc != 0:
        logger.error(f"Failed to connect to MQTT (v3.1.1): {mqtt.connack_string(rc)}. Result code: {rc}")
        return
        
    logger.info(f"Connected to MQTT (v3.1.1) with result code {rc} ({mqtt.connack_string(rc)})")
    _post_connect_setup(client, userdata)

def on_connect_v5(client: mqtt.Client, userdata, flags, reason_code, properties):
    """MQTT v5.0 connection callback"""
    if reason_code.is_failure:
        logger.error(f"Failed to connect to MQTT (v5.0): {reason_code}.")
        return
        
    logger.info(f"Connected to MQTT (v5.0) with result code {reason_code}.")
    _post_connect_setup(client, userdata)

def _post_connect_setup(client: mqtt.Client, userdata):
    """Common post-connection setup for both MQTT versions"""
    config = userdata['config']
    mqtt_conf = config['mqtt']
    base_topic = f"{mqtt_conf['prefix']}{mqtt_conf['device_prefix']}/{mqtt_conf['id']}"
    
    # Subscribe to control topics
    mute_topic = f"{base_topic}/mute/set"
    volume_topic = f"{base_topic}/volume/set"
    
    logger.info(f"Subscribing to MQTT control topics: {mute_topic}, {volume_topic}")
    
    client.subscribe(mute_topic)
    client.subscribe(volume_topic)
    
    # Home Assistant volume discovery
    volume_discovery_payload = {
        "name": f"{mqtt_conf['friendly_name']} Volume",
        "uniq_id": f"{mqtt_conf['id']}_volume",
        "device": {
            "name": mqtt_conf['device_name'],
            "ids": mqtt_conf['id'],
            "mf": mqtt_conf['device_manufacturer'],
            "mdl": mqtt_conf['device_model'],
            "sw": mqtt_conf['device_sw_version']
        },
        "avty_t": f"{base_topic}/availability",
        "cmd_t": f"{base_topic}/volume/set",
        "stat_t": f"{base_topic}/volume/state",
        "icon": "mdi:volume-high",
        "ret": True
    }
    client.publish(
        f"{mqtt_conf['discover_prefix']}/number/{mqtt_conf['device_prefix']}/{mqtt_conf['id']}_volume/config",
        json.dumps(volume_discovery_payload),
        retain=True
    )
    logger.info(f"Published Home Assistant volume discovery for '{mqtt_conf['friendly_name']}'.")
    
    # Home Assistant mute discovery
    mute_discovery_payload = {
        "name": f"{mqtt_conf['friendly_name']} Mute",
        "uniq_id": f"{mqtt_conf['id']}_mute",
        "device": {
            "name": mqtt_conf['device_name'],
            "ids": mqtt_conf['id'],
            "mf": mqtt_conf['device_manufacturer'],
            "mdl": mqtt_conf['device_model'],
            "sw": mqtt_conf['device_sw_version']
        },
        "avty_t": f"{base_topic}/availability",
        "cmd_t": f"{base_topic}/mute/set",
        "stat_t": f"{base_topic}/mute/state",
        "icon": "mdi:volume-mute",
        "ret": True
    }
    client.publish(
        f"{mqtt_conf['discover_prefix']}/switch/{mqtt_conf['device_prefix']}/{mqtt_conf['id']}_mute/config",
        json.dumps(mute_discovery_payload),
        retain=True
    )
    logger.info(f"Published Home Assistant mute discovery for '{mqtt_conf['friendly_name']}'.")
    
    # Publish initial states
    for device in userdata['devices'].values():
        initial_volume = device.volume_get()
        initial_mute = device.mute_get()
        client.publish(f"{device.volume_topic}/state", initial_volume)
        client.publish(f"{device.mute_topic}/state", "ON" if initial_mute else "OFF")
        logger.info(f"[{device.id}] Published initial state: Volume={initial_volume}%, Mute={'ON' if initial_mute else 'OFF'}.")
        
    client.publish(f"{base_topic}/availability", "online", retain=True)
    logger.info(f"Published availability 'online' for '{mqtt_conf['friendly_name']}'.")


def on_message(client, userdata, message):
    try:
        payload = message.payload.decode("utf-8").strip().upper()
        logger.info(f"Received MQTT message on '{message.topic}': '{payload}'")
        
        for device in userdata['devices'].values():
            if message.topic == f"{device.volume_topic}/set":
                if payload == 'UP':
                    device.volume_up()
                elif payload == 'DOWN':
                    device.volume_down()
                else:
                    try:
                        volume = int(payload)
                        if 0 <= volume <= 100:
                            device.volume_set(volume)
                        else:
                            logger.warning(f"[{device.id}] Received volume value '{payload}' out of range (0-100). Ignoring.")
                    except ValueError:
                        logger.warning(f"[{device.id}] Invalid volume value received: '{payload}'. Must be 'UP', 'DOWN', or an integer between 0-100.")
                        
            elif message.topic == f"{device.mute_topic}/set":
                if payload in ["ON", "1", "TRUE"]:
                    device.mute_set(True)
                elif payload in ["OFF", "0", "FALSE"]:
                    device.mute_set(False)
                else:
                    logger.warning(f"[{device.id}] Invalid mute command received: '{payload}'. Must be 'ON'/'1'/'TRUE' or 'OFF'/'0'/'FALSE'.")
                    
    except Exception as e:
        logger.error(f"Error processing MQTT message: {e}", exc_info=True)

def setup_syslog_logging(config: Dict[str, Any]):
    """Configures the logger to send messages to rsyslog and removes the initial console handler."""
    
    # Remove the initial console handler if it exists, to avoid duplicate logs after syslog is set up
    for handler in logger.handlers[:]: # Iterate over a copy to allow modification
        if isinstance(handler, logging.StreamHandler) and handler is console_handler:
            logger.removeHandler(handler)
            break

    mqtt_conf = config['mqtt']
    log_host = '192.168.0.15'
    log_port = 514

    try:
        syslog_handler = logging.handlers.SysLogHandler(address=(log_host, log_port), facility=logging.handlers.SysLogHandler.LOG_DAEMON)
        # Custom formatter to include client ID for rsyslog parsing (Host will be added by rsyslog itself)
        formatter = logging.Formatter(f'%(asctime)s - %(levelname)s - [{mqtt_conf["id"]}] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
        logger.info(f"Syslog logging initialized to {log_host}:{log_port}.")
    except Exception as e:
        # If syslog setup fails, re-add the console handler (if it was removed)
        # and log the error to the console.
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            logger.addHandler(console_handler)
        logger.error(f"Failed to setup syslog to {log_host}:{log_port}: {e}", exc_info=True)
        logger.warning("Proceeding with console logging only.")

def create_mqtt_client(config: Dict[str, Any], use_mqttv5: bool = False) -> mqtt.Client:
    """Create and configure MQTT client with version detection"""
    mqtt_conf = config['mqtt']
    
    if use_mqttv5:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=mqtt_conf['id'],
            protocol=mqtt.MQTTv5
        )
        client.on_connect = on_connect_v5
        logger.info(f"Creating MQTT v5 client with ID: {mqtt_conf['id']}")
    else:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION1,
            client_id=mqtt_conf['id'],
            protocol=mqtt.MQTTv311
        )
        client.on_connect = on_connect_v3
        logger.info(f"Creating MQTT v3.1.1 client with ID: {mqtt_conf['id']}")
        
    client.username_pw_set(mqtt_conf['user'], mqtt_conf['password'])
    return client

def main():
    # 1. Load config - logger is already initialized with a console handler, so this will work
    config = load_config() 
    
    # 2. Now that config is loaded, set up syslog logging with the MQTT ID
    setup_syslog_logging(config)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    mqtt_conf = config['mqtt']
    
    # Try MQTT v5 first, fall back to v3 if not available
    client = None
    try:
        client = create_mqtt_client(config, use_mqttv5=True)
    except AttributeError: # paho-mqtt might not expose MQTTv5 if old version
        logger.warning("MQTT v5 not available, falling back to MQTT v3.1.1")
        client = create_mqtt_client(config, use_mqttv5=False)
    except Exception as e: # Catch other potential errors during client creation
        logger.critical(f"Failed to create MQTT client: {e}. Exiting.", exc_info=True)
        sys.exit(1)
        
    # Setup devices
    devices = {
        dev_id: VolumeControl(dev_id, config, client)
        for dev_id, dev_config in config['devices'].items()
        if dev_config['platform'] == 'alsa'
    }
    
    client.user_data_set({'config': config, 'devices': devices})
    client.on_message = on_message
    
    # Set last will
    client.will_set(
        f"{mqtt_conf['prefix']}{mqtt_conf['device_prefix']}/{mqtt_conf['id']}/availability",
        "offline",
        retain=True
    )
    
    try:
        logger.info(f"Connecting to MQTT broker at {mqtt_conf['host']}:{mqtt_conf['port']}...")
        client.connect(mqtt_conf['host'], mqtt_conf['port'])
        client.loop_start()
        
        logger.info("Service started. Waiting for messages and monitoring ALSA events...")
        while not shutdown_flag:
            for device in devices.values():
                # Check for ALSA events first
                if device.check_for_changes():
                    # If changes were detected, skip the periodic publish this cycle
                    continue
                
                # Otherwise, proceed with periodic publishing if needed
                device.publish_current_state()
                
            # Short sleep to prevent CPU overload
            time.sleep(0.1)
            
    except Exception as e:
        logger.critical(f"Error in main loop: {e}", exc_info=True)
    finally:
        logger.info("Shutting down...")
        client.publish(
            f"{mqtt_conf['prefix']}{mqtt_conf['device_prefix']}/{mqtt_conf['id']}/availability",
            "offline",
            retain=True
        )
        client.loop_stop()
        client.disconnect()
        logger.info("Cleanup complete. Service stopped.")

if __name__ == "__main__":
    main()
