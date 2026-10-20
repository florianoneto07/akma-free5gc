#!/usr/bin/env bash
# Give a subscriber an AKMA subscription in the UDR of free5GC, or take it
# away. Runs on the free5GC host (needs mongosh).
#
# Usage: provision-akma-subscriber.sh <supi> <routing-indicator>
#        provision-akma-subscriber.sh <supi> --revoke
#
# Sets, in the authentication subscription of <supi> (MongoDB database
# "free5gc", collection subscriptionData.authenticationData.
# authenticationSubscription), the attributes of TS 29.505 table 5.4.2.2-1:
#   akmaAllowed: true
#   routingId:   the Routing Indicator of the SUCI of the subscriber, as a
#                string of 1 to 4 digits ("0000" is not "0")
# --revoke removes both attributes.
#
# Editing the subscriber in the free5GC web console rewrites the document
# and drops these attributes: run this script again afterwards.
set -euo pipefail

supi="${1:?usage: provision-akma-subscriber.sh <supi> <routing-indicator>|--revoke}"
arg="${2:?usage: provision-akma-subscriber.sh <supi> <routing-indicator>|--revoke}"
db="${MONGO_URL:-mongodb://127.0.0.1:27017/free5gc}"
coll="subscriptionData.authenticationData.authenticationSubscription"

[[ "$supi" =~ ^imsi-[0-9]{5,15}$ ]] || { echo "SUPI must be imsi-<5 to 15 digits>" >&2; exit 1; }
if [ "$arg" = --revoke ]; then
    update='{"$unset": {"akmaAllowed": "", "routingId": ""}}'
else
    [[ "$arg" =~ ^[0-9]{1,4}$ ]] || { echo "Routing Indicator must be 1 to 4 digits" >&2; exit 1; }
    update="{\"\$set\": {\"akmaAllowed\": true, \"routingId\": \"$arg\"}}"
fi

mongosh --quiet "$db" --eval "
const r = db.getCollection('$coll').updateOne({ueId: '$supi'}, $update);
if (r.matchedCount !== 1) { print('subscriber $supi not found'); quit(1); }
const d = db.getCollection('$coll').findOne({ueId: '$supi'}, {_id: 0, ueId: 1, authenticationMethod: 1, akmaAllowed: 1, routingId: 1});
printjson(d);
"
