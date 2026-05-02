# Manual Map Injector

A lightweight, interactive C++ DLL Injector currently in development. It utilizes manual mapping to inject payloads directly into target process memory.

## Features

*   **Manual Mapping**: Bypasses standard Windows API loaders (`LoadLibrary`).
*   **Thread Hijacking**: Uses thread context manipulation (EIP/RIP) for stealthy payload execution, avoiding highly-monitored remote thread creation.
*   **Interactive Console**: Simple drag-and-drop CLI interface for quick testing.

## Credits & Thanks

Huge thanks to **TheCruZ** for providing the original foundation and manual mapping engine for this project. 
Original Source: [https://github.com/TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector)