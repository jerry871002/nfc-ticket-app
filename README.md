# NFC Ticket App

This is a course project of CS-E4300 Network Security at Aalto University.

This project implements an Android app for a multi-ride amusement park ticket system using an NFC memory card platform called NXP MIFARE Ultralight C smart card.

One of the key goals is to develop a secure protocol for communication between the reader and the NFC card, as well as to establish an appropriate data structure on the NFC card.

Key features of the application include
- Issue tickets with a constant number of rides
- Validate the ticket (check expiry time and remaining rides, decrement remaining rides)
- The tickets are valid for a certain period of time (usually one day, but you can use one minute for testing) from the time when they were issued
- Start the validity period only when the ticket is used for the first time (they can be given as gifts)
- If the tickets have expired or they have been fully used, reformat the card and issue a new ticket (savings on blank tickets and friendlier to the environment)
- Issue additional rides (+5) to a card without erasing any still valid ticket
