# Task 1 - Introduction

Windows internals are core to how the Windows operating system functions; this provides adversaries with a lucrative target for nefarious use. Windows internals can be used to hide and execute code, evade detections, andchain with other techniques or exploits.

The term Windows internals can encapsulate any component found on the back-end of the Windows operating system.
This can include processes, file formats, COM (Component Object Model), task scheduling, I/O System, etc. Thisroom will focus on abusing and exploiting processes and their components, DLLs (Dynamic Link Libraries), and the PE (Portable Executable) format.

## Learning Objectives

1. Understand how internal components are vulnerable
2. Learn how to abuse and exploit Windows Internals vulnerabilities
3. Understand mitigations and detections for the techniques
4. Apply techniques learned to a real-world adversary case study

Before beginning this room, familiarize yourself with basic Windows usage and functionality. We recommend completing the Windows Internals room. Basic programming knowledge in C++ and PowerShell is also recommended but not required.

We have provided a base Windows machine with the files needed to complete this room. You can access the machine in-browser or through RDP using the credentials below.

| Machine IP | Username | Password |
|---|---|---|
| 10.66.145.59 | THM-Attacker | Tryhackme! |

This is going to be a lot of information. Please buckle your seatbelts and locate your nearest fire extinguisher.

Don't forget to tip your team on the way out!

