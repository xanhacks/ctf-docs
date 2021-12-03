---
title: Intruder tab
description: Burpsuite intruder tab cheatsheets
---

# Burpsuite Intruder tab

## List of Attack Types

### Sniper

The sniper attack uses only one payload set, and it replaces only one position at a time. It loops through the payload set, first replacing only the first marked position with the payload and leaving all other positions to their original value. After its done with the first position, it continues with the second position.

### Battering ram

The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.

### Pitch fork

The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

### Cluster bomb

The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

> References [sjoerdlangkemper.nl](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/).

## Payloads

Payload processing allows you to perform checks or operations on your payload sets.

You can remove or add characters to the payload URL encoding section, it can be usefull if you are using bad characters.

## Options

You can remove the first default request in the attack results by unchecking the "Make unmodified baseline request".

### Grep - Match

You can search for string in the response. Exemple with user enumeration via error message :

![User enumeration via error message]({{ base_url }}/assets/img/web/burp_intruder_grep_match.png)

In the exemple below, 'ansible' is a valid username.
