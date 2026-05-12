#!/usr/bin/env bash
set -euo pipefail

DEFAULT_HOST="fit-workspaces.ksi.fit.cvut.cz"

USERNAME="${1:-}"
OWNER_REPO="${2:-}"

if [[ -z "$USERNAME" || -z "$OWNER_REPO" ]]; then
  echo "Usage:"
  echo "  $(basename "$0") <username> <owner/repo> [options]"
  echo
  echo "Arguments:"
  echo "  username            Username owning the workspace"
  echo "  owner/repo          GitHub repository in the form <owner>/<repo>"
  echo
  echo "Options:"
  echo "  --host <host>       SSH gateway host (default: ${DEFAULT_HOST})"
  echo "  --ref <ref>         Git reference to use (branch, tag, or commit SHA)"
  echo "  --pod <pod>         Pod name to target a specific workspace pod"
  echo "  --namespace <ns>    Kubernetes namespace of the pod (requires --pod)"
  echo
  echo "If --ref is not specified, the default repository ref is used."
  exit 1
fi

shift 2

HOST="${DEFAULT_HOST}"
REF_NAME=""
POD_NAME=""s
NAMESPACE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      [[ -n "$HOST" ]] || { echo "Error: --host requires a value"; exit 1; }
      shift 2
      ;;
    --ref)
      REF_NAME="${2:-}"
      [[ -n "$REF_NAME" ]] || { echo "Error: --ref requires a value"; exit 1; }
      shift 2
      ;;
    --pod)
      POD_NAME="${2:-}"
      [[ -n "$POD_NAME" ]] || { echo "Error: --pod requires a value"; exit 1; }
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      [[ -n "$NAMESPACE" ]] || { echo "Error: --namespace requires a value"; exit 1; }
      shift 2
      ;;
    *)
      echo "Error: unknown option '$1'"
      exit 1
      ;;
  esac
done

if [[ -n "$NAMESPACE" && -z "$POD_NAME" ]]; then
  echo "Error: --namespace requires --pod"
  exit 1
fi

USER_STRING="${USERNAME}~repo=${OWNER_REPO}"

if [[ -n "$REF_NAME" ]]; then
  USER_STRING+="+ref=${REF_NAME}"
fi

if [[ -n "$POD_NAME" ]]; then
  USER_STRING+="+pod=${POD_NAME}"
  if [[ -n "$NAMESPACE" ]]; then
    USER_STRING+="+ns=${NAMESPACE}"
  fi
fi

ENCODED="$(
  printf '%s' "$USER_STRING" \
  | base64 -w0 \
  | tr '+/' '-_' \
  | tr -d '='
)"

REPO_NAME="${OWNER_REPO##*/}"

code -n --folder-uri="vscode-remote://ssh-remote+b64-${ENCODED}@${HOST}/home/${USERNAME}/${REPO_NAME}"
