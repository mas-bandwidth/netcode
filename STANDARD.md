# netcode.io 1.0

This document describes the binary standard for the netcode.io, so that implementations of this protocol can be created in different languages.

## Overview

**netcode.io** is a simple protocol for creating secure client/server connections over UDP.

It's functionality can be summarized

0. A web backend authenticates a client (outside the scope of this standard)

1. When that client wants to play a game, the backend generates a short lived _connect token_ and passes it to the client over HTTPS.

2. The client uses that connect token is used by that client to establish a secure connection to a dedicated server over UDP.

3. The dedicated server runs logic to ensure that only authenticated clients with connect tokens may connect to the server.

4. Once connection is established between a client and server, all packets sent over UDP and encrypted and signed.

## General Conventions


## Connect Token Structure

The first aspect of 

## Packet Structure

## Connect Token

## Challenge Token

## Client State Machine

## Server Connection Processing

