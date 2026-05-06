# vhs script for the README demo GIF.
# Run with: vhs assets/demo.tape  (requires https://github.com/charmbracelet/vhs)
# Output:   assets/demo.gif
#
# The script picks PID 1 by default — replace with any PID you want to record.
# It walks F1 → F2 → ... → F7, pausing briefly on each tab.

Output assets/demo.gif

Set FontSize 14
Set Width  1280
Set Height 720
Set Theme  "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

# Boot
Type "sudo ./bin/ptop --pid 1"
Sleep 600ms
Enter
Sleep 4s

# Walk through tabs
Tab
Sleep 3s
Tab
Sleep 3s
Tab
Sleep 3s
Tab
Sleep 3s
Tab
Sleep 3s
Tab
Sleep 3s

# Help overlay
Type "?"
Sleep 3s
Type "?"

# Pause + filter demo
Sleep 1s
Type "p"
Sleep 1s
Type "p"

# Quit cleanly
Type "q"
Sleep 1s
