#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient

PLC_IP = "10.66.176.73"
PORT = 502
UNIT_ID = 1

# Defaults in case reads fail (avoid "possibly unbound" variables later)
hr0 = hr1 = hr2 = hr3 = hr4 = None
c10 = c11 = c12 = c13 = c14 = c15 = None


# Connect to PLC
client = ModbusTcpClient(PLC_IP, port=PORT)

if not client.connect():
    print("Failed to connect to PLC")
    exit(1)

print("=" * 60)
print("TBFC Drone System - Reconnaissance Report")
print("=" * 60)
print()

# Read holding registers
print("HOLDING REGISTERS:")
print("-" * 60)

registers = client.read_holding_registers(address=0, count=5, slave=UNIT_ID)
if not registers.isError():
    hr0, hr1, hr2, hr3, hr4 = registers.registers

    print(f"HR0 (Package Type): {hr0}")
    print("  0=Christmas, 1=Eggs, 2=Baskets")
    print()

    print(f"HR1 (Delivery Zone): {hr1}")
    print("  1-9=Normal zones, 10=Ocean dump")
    print()

    print(f"HR4 (System Signature): {hr4}")
    if hr4 == 666:
        print("  WARNING: Eggsploit signature detected")
    print()

# Read coils
print("COILS (Boolean Flags):")
print("-" * 60)

coils = client.read_coils(address=10, count=6, slave=UNIT_ID)
if not coils.isError():
    c10, c11, c12, c13, c14, c15 = coils.bits[:6]

    print(f"C10 (Inventory Verification): {c10}")
    print("  Should be True")
    print()

    print(f"C11 (Protection/Override): {c11}")
    if c11:
        print("  ACTIVE - System monitoring for changes")
    print()

    print(f"C12 (Emergency Dump): {c12}")
    if c12:
        print("  CRITICAL: Dump protocol active")
    print()

    print(f"C13 (Audit Logging): {c13}")
    print("  Should be True")
    print()

    print(f"C14 (Christmas Restored): {c14}")
    print("  Auto-set when system is fixed")
    print()

    print(f"C15 (Self-Destruct Armed): {c15}")
    if c15:
        print("  DANGER: Countdown active")
    print()

print("=" * 60)
print("THREAT ASSESSMENT:")
print("=" * 60)

if hr4 == 666:
    print("Eggsploit framework detected")
if c11 is True:
    print("Protection mechanism active - trap is set")
if hr0 == 1:
    print("Package type forced to eggs")
if c10 is False:
    print("Inventory verification disabled")
if c13 is False:
    print("Audit logging disabled")

print()
print("REMEDIATION REQUIRED")
print("=" * 60)

client.close()
