# shenv — README demo tape.
#
# Recorded by `bash scripts/demo.sh`, which builds shenv and hands this tape a
# throwaway world in $TMPDIR: a bare git remote, bob's work tree, alice's clone, and
# a separate HOME for each of them. Every secret, key and teammate on screen is
# invented, and shenv runs against HOMEs of its own, so this can be re-recorded by
# anyone without exposing a real key, repo or secret.
#
# Run it only through the script — on its own it would record shenv against your own
# ~/.shenv key and whatever repo you happen to be standing in.

Output assets/demo.gif

Require shenv
Require git

Set Shell "bash"
Set FontSize 15
# Sized to the tallest act (bob's init + seal, ~26 lines) plus headroom, not to a
# round default: dead space below the prompt is dead pixels in the README, and
# anything taller than the window scrolls, which breaks every later Wait+Screen.
# Width is set by the pasted add-member line, the longest thing on screen: 129
# characters of command plus a 17-character prompt is 146 columns. Usable columns are
# roughly (Width - 2*Padding - 2*Margin) / 9.7px at FontSize 15, so 1500 gives 145 and
# wraps by one character. 1600 gives ~155, which leaves room for the prompt to grow.
Set Width 1600
Set Height 640
Set Padding 26
Set Margin 18
Set MarginFill "#1a1420"
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set Framerate 24

Hide
Type "source $DEMO_SETUP" Enter
Sleep 1s
Type "clear" Enter
Show

# ---- bob seals the secrets ----

Type "cat .env" Enter
Sleep 1800ms

# Empty passphrase: one Enter, no confirm prompt. A passphrase would make every later
# command block on a prompt nobody watching a GIF can answer.
Type "shenv init bob" Enter
Wait+Screen /passphrase/
Sleep 800ms
Enter
Wait+Screen /Registered/
Sleep 1600ms

Type "shenv seal" Enter
Wait+Screen /Encrypted/
Sleep 1400ms

# The whole point, in four lines: what gets committed is ciphertext.
Type "head -4 env.shenv" Enter
Sleep 2200ms

# Wipe between acts. VHS's Wait+Screen only matches what is still on the visible
# screen — once output scrolls off, every later wait times out even though the text
# it wants was printed. Each act therefore starts on a clean screen.
Hide
Type "clear" Enter
Show

# ---- alice asks to be let in ----

Type "become alice" Enter
Sleep 700ms

# `whoami` prints the exact line a teammate has to run. That one line is the whole
# onboarding handshake, so the demo rests on it long enough to read.
Type "shenv whoami" Enter
Wait+Screen /add-member/
Sleep 2600ms

Hide
Type "clear" Enter
Show

# ---- bob pastes it ----

Type "become bob" Enter
Sleep 700ms

# The line alice just printed, pasted — which is what you would actually do with it.
# Copy/Paste puts all 130 characters on screen in a single frame; typing them even at
# 8ms is a second of cursor crawl for a key nobody reads character by character.
# The Copy line is written by scripts/demo.sh, because her keys are fresh every run.
Source demo/.add-member.tape
Paste
Sleep 900ms
Enter
Wait+Screen /Added/
Sleep 1400ms

# Re-sealing for a changed team asks first — that confirmation is the feature, so the
# demo shows it rather than skipping past it.
Type "shenv seal" Enter
Wait+Screen@8s /Continue/
Sleep 1600ms
Type "y" Enter
Wait+Screen /Encrypted/
Sleep 1400ms

Type "git add -A && git commit -qm share && git push -q" Enter
Sleep 1200ms

Hide
Type "clear" Enter
Show

# ---- alice, on her own machine ----

Type "become alice" Enter
Sleep 700ms

# Only the encrypted blob and the public recipient list ever travelled.
Type "git pull -q && ls" Enter
Sleep 1800ms

Type "shenv open" Enter
Wait+Screen@8s /Wrote/
Sleep 1600ms

Type "cat .env" Enter
Sleep 2400ms

# Rest, so the loop does not snap on the last line.
Sleep 1200ms
