import os
import sys
import time
import random

import traci  # pip install traci if needed

# --------------------------
# CONFIGURATION
# --------------------------
SUMO_CFG = "twoIntersection.sumocfg"    # Your SUMO config file
STOP_TIME_THRESHOLD = 5                 # # of consecutive steps stopped -> anomaly
UNAUTHORIZED_VEHICLE_PREFIX = "unauth"  # Prefix for unauthorized vehicles

# Track how long vehicles have been at speed=0
stop_counters = {}


def run_simulation():
    """
    Main function that starts SUMO, runs the simulation step-by-step,
    injects anomalies, and detects them.
    """
    # 1) Build the sumo command in 'server' mode so TraCI can connect
    #    If you do NOT want the GUI, replace "sumo-gui" with "sumo".
    sumo_cmd = [
        "sumo-gui",
        "-c", SUMO_CFG,
        "--start",
        "--no-step-log", "true"
    ]

    # 2) Start SUMO with TraCI
    traci.start(sumo_cmd)
    print("[INFO] SUMO simulation started with TraCI.")

    # 3) Run the simulation for 300 steps
    for step in range(300):
        traci.simulationStep()  # advance one step in the simulation

        # Inject a random stop at step 50
        if step == 50:
            inject_sudden_stop_anomaly()

        # Inject an unauthorized vehicle at step 100
        if step == 100:
            inject_unauthorized_vehicle()

        # Check for anomalies each step
        detect_anomalies()

    # 4) Close TraCI when done
    print("[INFO] Simulation finished.")


def inject_sudden_stop_anomaly():
    """
    Force a random vehicle to stop (speed=0). 
    Simulates a sudden breakdown or malicious halt.
    """
    vehicle_ids = traci.vehicle.getIDList()
    if not vehicle_ids:
        return
    veh_to_stop = random.choice(vehicle_ids)
    print(f"[Anomaly Injection] Forcing {veh_to_stop} to stop.")
    traci.vehicle.setSpeed(veh_to_stop, 0.0)


def inject_unauthorized_vehicle():
    """
    Insert a new vehicle onto the network with an ID that
    wasn't part of the original flow. Simulates an intruder vehicle.
    """
    new_id = UNAUTHORIZED_VEHICLE_PREFIX + str(int(time.time()))
    # Must pick a route ID that exists in your .rou.xml, e.g. "route_0" or "route_1".
    route_id = "route_0"  
    try:
        traci.vehicle.add(vehID=new_id, routeID=route_id, departPos="0", departSpeed="max", typeID="car")
        print(f"[Anomaly Injection] Injecting unauthorized vehicle: {new_id}")
    except traci.exceptions.TraCIException as e:
        print(f"[ERROR] Could not inject unauthorized vehicle: {e}")


def detect_anomalies():
    """
    Simple anomaly detection rules:
      - A vehicle that stays at 0 speed for STOP_TIME_THRESHOLD steps
      - A vehicle whose ID starts with UNAUTHORIZED_VEHICLE_PREFIX
    """
    global stop_counters
    vehicle_ids = traci.vehicle.getIDList()

    for vid in vehicle_ids:
        # 1) Speed-based anomaly (prolonged stop)
        speed = traci.vehicle.getSpeed(vid)
        if speed < 0.1:  # Consider as "stopped"
            stop_counters[vid] = stop_counters.get(vid, 0) + 1
            if stop_counters[vid] == STOP_TIME_THRESHOLD:
                print(f"[ANOMALY DETECTED] {vid} has been stopped for {STOP_TIME_THRESHOLD} steps.")
        else:
            stop_counters[vid] = 0

        # 2) Unauthorized vehicle detection
        if vid.startswith(UNAUTHORIZED_VEHICLE_PREFIX):
            print(f"[ANOMALY DETECTED] Unauthorized vehicle on network: {vid}")


if __name__ == "__main__":
    run_simulation()
