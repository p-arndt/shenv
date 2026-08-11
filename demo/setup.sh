# Sourced by demo/shenv.tape as `source $DEMO_SETUP`, inside the recording but
# hidden from it. scripts/demo.sh has already built shenv and stood up the
# throwaway world this points at; nothing here touches anything real.

export PATH="$DEMO_ROOT/bin:$PATH"
export SHENV_NO_UPDATE_CHECK=1     # or the demo records an update nag
export PAGER=cat GIT_PAGER=cat
export EDITOR=true

# Two machines, one shell. `become` swaps the HOME shenv reads its key from, the
# working copy, and the prompt — so the story stays legible without cutting
# between windows. The prompt is set explicitly rather than inherited: bash's
# default would put the real user and hostname on screen.
become() {
  case "$1" in
    bob)
      export HOME="$DEMO_ROOT/bob-home"
      cd "$DEMO_ROOT/api" || return
      PS1='\[\e[38;5;213m\]bob\[\e[0m\]\[\e[2m\]@laptop\[\e[0m\] \[\e[38;5;117m\]api\[\e[0m\] \[\e[2m\]$\[\e[0m\] '
      ;;
    alice)
      export HOME="$DEMO_ROOT/alice-home"
      cd "$DEMO_ROOT/clone" || return
      PS1='\[\e[38;5;150m\]alice\[\e[0m\]\[\e[2m\]@laptop\[\e[0m\] \[\e[38;5;117m\]api\[\e[0m\] \[\e[2m\]$\[\e[0m\] '
      ;;
  esac
}

become bob
