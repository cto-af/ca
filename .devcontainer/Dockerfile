FROM mcr.microsoft.com/devcontainers/javascript-node:4.0.6-trixie

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
   && apt-get -y upgrade && apt-get install -y dbus-x11 gnome-keyring

RUN SNIPPET='eval $(dbus-launch --sh-syntax) && eval $(echo -n test | gnome-keyring-daemon --unlock)' \
  && echo "$SNIPPET" >> "/home/node/.bashrc"
