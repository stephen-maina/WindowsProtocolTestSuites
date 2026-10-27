#!/usr/bin/env bash
# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
#
# Linux counterpart of Create-SMB2Env.ps1: creates the shares the FileServer SMB2 suite expects on a Linux SUT
# running ksmbd (kernel SMB server) or Samba. Idempotent; run as root on the SUT.
#
#   sudo ./Create-SMB2Env-Linux.sh --user administrator [--server auto|ksmbd|samba] [--root /srv/smb]
#                                  [--min-protocol SMB2_02] [--enable-durable] [--password <pw>]
#
#   --second-user <name>  creates a second, non-admin local account (matches Common.NonAdminUserName, e.g. nonadmin),
#                     gives it --password and lets it access every share. Establishes the second-user connection
#                     prerequisite for applicable tests; it does not change different-owner reconnect assertions.
#                     Requires setfacl and an ACL-capable filesystem; grants named-user/default ACLs, not force user.
#   --enable-durable  (ksmbd) sets "smb2 leases = yes" and "durable handles = yes" in [global]; both default to no.
#
# Shares created (same names as the Windows script):
#   FileShare, SMBBasic (+ symlinks), SameWithSMBBasic, DifferentFromSMBBasic, ShareForceLevel2,
#   SMBEncrypted, SMBCompressed, SMBReFSShare
#
# Product limits (the script warns, the test suite gates on the matching feature flags / Platform):
#   * ksmbd has only a global "smb3 encryption" switch, so SMBEncrypted cannot be forced per share there.
#     Samba supports it per share ("smb encrypt = required").
#   * Neither server implements SMB2 compression, so SMBCompressed exists but never reports SHAREFLAG_COMPRESS_DATA.
#   * There is no ReFS/FAT32 volume; SMBReFSShare is a plain directory.
set -euo pipefail

SERVER=auto
ROOT=/srv/smb
USER_NAME=administrator
PASSWORD=
MIN_PROTOCOL=
ENABLE_DURABLE=0
SECOND_USER=

while [ $# -gt 0 ]; do
    case "$1" in
        --server) SERVER=$2; shift 2;;
        --root) ROOT=$2; shift 2;;
        --user) USER_NAME=$2; shift 2;;
        --password) PASSWORD=$2; shift 2;;
        --min-protocol) MIN_PROTOCOL=$2; shift 2;;
        --enable-durable) ENABLE_DURABLE=1; shift;;
        --second-user) SECOND_USER=$2; shift 2;;
        -h|--help) sed -n '2,24p' "$0"; exit 0;;
        *) echo "Unknown argument: $1" >&2; exit 2;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
id "$USER_NAME" >/dev/null 2>&1 || { echo "Local user '$USER_NAME' does not exist." >&2; exit 1; }

VALID_USERS=$USER_NAME
if [ -n "$SECOND_USER" ]; then
    command -v setfacl >/dev/null 2>&1 || { echo "--second-user requires setfacl (the acl package)." >&2; exit 1; }
    id "$SECOND_USER" >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin "$SECOND_USER"
    VALID_USERS="$USER_NAME,$SECOND_USER"
fi

if [ "$SERVER" = auto ]; then
    if [ -d /etc/ksmbd ] && command -v ksmbd.control >/dev/null 2>&1; then SERVER=ksmbd
    elif command -v smbd >/dev/null 2>&1; then SERVER=samba
    else echo "Neither ksmbd nor Samba found; use --server." >&2; exit 1; fi
fi

case "$SERVER" in
    ksmbd) CONF=/etc/ksmbd/ksmbd.conf;;
    samba) CONF=/etc/samba/smb.conf;;
    *) echo "--server must be auto, ksmbd or samba." >&2; exit 2;;
esac
[ -f "$CONF" ] || { echo "$CONF not found." >&2; exit 1; }

BEGIN="# BEGIN WPTS-SMB2-ENV (managed by Create-SMB2Env-Linux.sh)"
END="# END WPTS-SMB2-ENV"

echo "Server: $SERVER  Config: $CONF  Root: $ROOT  User: $USER_NAME"

prepare_share_directory() {
    local directory=$1
    mkdir -p "$directory"
    chown "$USER_NAME" "$directory"
    chmod 0770 "$directory"
    if [ -n "$SECOND_USER" ]; then
        # Both identities need inherited access; the creating user's ownership stays distinct.
        setfacl -m "u:$SECOND_USER:rwx,m::rwx,d:u::rwx,d:u:$USER_NAME:rwx,d:u:$SECOND_USER:rwx,d:g::rwx,d:m::rwx,d:o::---" "$directory"
    fi
}

for d in FileShare SMBBasic DifferentFromSMBBasic ShareForceLevel2 SMBEncrypted SMBCompressed SMBReFSShare; do
    prepare_share_directory "$ROOT/$d"
done

# Same layout as Create-SMB2Env.ps1: SMBBasic\symboliclink -> FileShare and SMBBasic\sub\symboliclink2 -> FileShare.
prepare_share_directory "$ROOT/SMBBasic/sub"
ln -sfn "$ROOT/FileShare" "$ROOT/SMBBasic/symboliclink"
ln -sfn "$ROOT/FileShare" "$ROOT/SMBBasic/sub/symboliclink2"

share_block() {
    # $1 name, $2 path, $3 extra lines
    printf '[%s]\n    path = %s\n    read only = no\n    valid users = %s\n%s' "$1" "$2" "$VALID_USERS" "$3"
}

BLOCK="$BEGIN
$(share_block FileShare "$ROOT/FileShare" "")
$(share_block SMBBasic "$ROOT/SMBBasic" "")
$(share_block SameWithSMBBasic "$ROOT/SMBBasic" "")
$(share_block DifferentFromSMBBasic "$ROOT/DifferentFromSMBBasic" "")
$(share_block ShareForceLevel2 "$ROOT/ShareForceLevel2" "")
$(share_block SMBCompressed "$ROOT/SMBCompressed" "")
$(share_block SMBReFSShare "$ROOT/SMBReFSShare" "")"

if [ "$SERVER" = samba ]; then
    BLOCK="$BLOCK
$(share_block SMBEncrypted "$ROOT/SMBEncrypted" "    smb encrypt = required
")"
else
    BLOCK="$BLOCK
$(share_block SMBEncrypted "$ROOT/SMBEncrypted" "")"
    echo "WARNING: ksmbd cannot require encryption per share (only global 'smb3 encryption'); SMBEncrypted will not report SHAREFLAG_ENCRYPT_DATA."
fi
BLOCK="$BLOCK
$END"
echo "WARNING: $SERVER does not implement SMB2 compression; SMBCompressed will not report SHAREFLAG_COMPRESS_DATA."

cp -n "$CONF" "$CONF.wpts-orig" 2>/dev/null || true
# Remove a previous managed block, then append the new one.
TMP=$(mktemp)
awk -v b="$BEGIN" -v e="$END" '$0==b{skip=1} !skip{print} $0==e{skip=0}' "$CONF" > "$TMP"
printf '\n%s\n' "$BLOCK" >> "$TMP"
cat "$TMP" > "$CONF"
rm -f "$TMP"

set_global() {
    # $1 key, $2 value: replace the key if present, otherwise add it under [global]
    if grep -qE "^\s*$1\s*=" "$CONF"; then
        sed -i -E "s|^\s*$1\s*=.*|    $1 = $2|" "$CONF"
    elif grep -qE '^\[global\]' "$CONF"; then
        sed -i -E "0,/^\[global\]/s||[global]\n    $1 = $2|" "$CONF"
    else
        printf '[global]\n    %s = %s\n' "$1" "$2" | cat - "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"
    fi
    echo "$1 = $2"
}

[ -z "$MIN_PROTOCOL" ] || set_global "server min protocol" "$MIN_PROTOCOL"

# ksmbd ships with leases and durable handles disabled, so the durable/replay/lease/AppInstanceId tests fail
# unless they are switched on. Samba enables them by default.
if [ "$ENABLE_DURABLE" = 1 ]; then
    if [ "$SERVER" = ksmbd ]; then
        set_global "smb2 leases" yes
        set_global "durable handles" yes
    else
        echo "--enable-durable is only needed for ksmbd; Samba already supports leases and durable handles."
    fi
fi

if [ -n "$PASSWORD" ]; then
    if [ "$SERVER" = samba ]; then
        printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | smbpasswd -a -s "$USER_NAME"
    else
        ksmbd.adduser -u -p "$PASSWORD" "$USER_NAME" 2>/dev/null || ksmbd.adduser -a -p "$PASSWORD" "$USER_NAME"
    fi
fi

if [ -n "$SECOND_USER" ] && [ -n "$PASSWORD" ]; then
    if [ "$SERVER" = samba ]; then
        printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | smbpasswd -a -s "$SECOND_USER"
    else
        ksmbd.adduser -u -p "$PASSWORD" "$SECOND_USER" 2>/dev/null || ksmbd.adduser -a -p "$PASSWORD" "$SECOND_USER"
    fi
fi

if [ "$SERVER" = samba ]; then
    testparm -s "$CONF" >/dev/null
    systemctl reload smbd 2>/dev/null || systemctl restart smbd
else
    # The ksmbd daemon rereads its configuration when asked to restart; the kernel module keeps running.
    systemctl restart ksmbd
fi

echo "Done. Shares:"
grep -E '^\[' "$CONF" | tr -d '[]' | sort -u
