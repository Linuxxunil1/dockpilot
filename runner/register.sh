#!/bin/sh
# Runner einmalig registrieren — danach bleibt die Config in gitlab-runner-config Volume.
# Aufruf: ./register.sh <GITLAB_URL> <REGISTRATION_TOKEN>
#
# Token findest du auf GitLab unter:
#   Settings → CI/CD → Runners → New project runner → Token kopieren

GITLAB_URL="${1:-https://gitlab.com}"
TOKEN="${2:?Bitte Token als zweites Argument angeben}"

docker compose run --rm gitlab-runner register \
  --non-interactive \
  --url "$GITLAB_URL" \
  --token "$TOKEN" \
  --executor docker \
  --docker-image docker:27-cli \
  --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
  --docker-privileged false \
  --description "dockpilot-runner" \
  --tag-list "dockpilot,docker"
