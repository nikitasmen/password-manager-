#ifndef SERVE_H
#define SERVE_H

// `password_manager --serve [--role server|peer] [--port N]`: this computer hosts the vault for other devices
// (docs/PROTOCOL.md §6-10), from its own local vault file, while this terminal stands in for the board's BOOT
// button. Returns the exit code.
int runServe(int argc, char** argv);

#endif  // SERVE_H
