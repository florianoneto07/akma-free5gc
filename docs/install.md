# Installation guide

What to do **after installing free5GC** with the official guide to use AKMA (3GPP TS 33.535). Each part builds on the previous one, and each ends with a check.

| Part | Content |
|---|---|
| 1 | Requirements and addresses |
| 2 | Check the key derivations |
| 3 | Install the AAnF |
| 4 | Enable AKMA in the UDM and the AUSF; provision a subscriber |
| 5 | AKMA in the logs of free5GC and UERANSIM |
| 6 | Run the test AF |
| 7 | Prepare the UE for Ua\* |
| 8 | End-to-end run |
| 9 | AF outside the operator network, anonymous access, context removal |
| 10 | UERANSIM on another host |
| 11 | Undo |

---

## 1. Requirements

| Item | Version |
|---|---|
| free5GC | v4.2.3, installed with the official guide, `TestRegistration` passing |
| MongoDB | the one of the guide, with `mongosh` (parts 3 and 4) |
| Go | 1.26.2, the version of free5GC v4.2.3 |
| Python | 3.10 or newer on the AF host (oracle and negative tests) |
| UERANSIM | v3.2.6, commit `85a0fbf` of the free5GC guide |

The reference setup has two hosts: free5GC, the AAnF and UERANSIM on one, and the AF and this repository on the other. One host is enough for parts 1 and 2. Part 10 moves UERANSIM to a third host, as in the free5GC guide.

If Go is missing, install it in your home directory, without root:

```bash
mkdir -p ~/sdk/go1.26.2 && curl -fsSL https://go.dev/dl/go1.26.2.linux-amd64.tar.gz | tar -xz -C ~/sdk/go1.26.2 --strip-components=1
```

```bash
export PATH=$HOME/sdk/go1.26.2/bin:$PATH
```

Check the SHA-256 of the archive against the one published at https://go.dev/dl/ before you use it.

### 1.1 Before part 3

**Clone the repository on both hosts.**

- On the AF host, clone it anywhere. Commands without `~/` run from its root.
- On the free5GC host, clone it as `~/akma-free5gc`, next to `~/free5gc`. The scripts of parts 3 to 7 run from there, and the patched `go.mod` files of part 4 point to that folder by relative path.

```bash
git clone https://github.com/florianoneto07/akma-free5gc.git ~/akma-free5gc
```

**SSH with a key** from the AF host to the free5GC host. `deploy.sh` (section 3.4) and `e2e.sh` (part 8) do not ask for an SSH password.

**UERANSIM on the free5GC host.** The free5GC guide installs UERANSIM on a separate host and points the gNB to the AMF. On a single host there is one change: `amfConfigs` in `config/free5gc-gnb.yaml` goes from `127.0.0.1` to `127.0.0.18`, the `ngapIpList` of the AMF. Leave the rest as it is.

**The subscriber.** Use the default subscriber of the web console, `imsi-208930000000001`, with the operator code type **OPc**, which comes selected. The guide says to switch to "OP", but `free5gc-ue.yaml` of UERANSIM has `opType: 'OPC'`, and the guide's own note applies: the parameters have to match those of the UE.

**Ubuntu 18.04.** The guide expects Ubuntu 20.04 or newer. On 18.04, with kernel 5.4, four things change:

- MongoDB 5.0 from the `bionic` repository, since the 8.2 of the guide has no package for 18.04;
- Node.js 22 built for glibc 2.17, from unofficial-builds.nodejs.org, since the official build needs glibc 2.28;
- the web console with the manual alternative of the guide, since `make webconsole` runs `sudo corepack enable`;
- gcc 9 and CMake 3.17 or newer for UERANSIM.

### 1.2 Addresses

The commands and the example configurations use the example topology:

| Host | Address |
|---|---|
| free5GC host | 192.168.16.130 |
| AF host | 192.168.16.129 |
| UERANSIM host (part 10) | 192.168.16.131 |

With other addresses, change them in the commands and in these places:

| Where | Fields |
|---|---|
| `free5gc/config/aanfcfg.yaml` (section 3.2) | `sbi.registerIPv4`, `sbi.bindingIPv4`; `sourceAddresses` of `akma.authorizedAfs` (the AF host) and of `akma.authorizedNefs` (the free5GC host) |
| `~/free5gc/config/nefcfg.yaml`, after the configuration patch (section 9.1) | `sbi.registerIPv4`, `sbi.bindingIPv4`; `sourceAddresses` of `akma.authorizedAfs` |
| `~/free5gc/config/ausfcfg.yaml`, only for a fixed AAnF address (section 4.2) | `akma.aanfUri`, which the configuration patch leaves commented out |
| `af/config/afcfg.yaml` (section 6.2) | `listen`, `aanfUri` |
| `af/config/afcfg-external.yaml` (section 9.2) | `listen`, `nefUri` |
| `seed` | `--aanf`, default `http://192.168.16.130:8010` |
| `uaclient` | `-connect`, default `192.168.16.129:8080` |
| `e2e.sh` | its argument, `user@host` of the free5GC host |

If you edit `nefcfg.yaml` after the configuration patch, `patch-nf.sh config revert` no longer reverses that patch. Revert by hand, or put your addresses in `free5gc/patches/config/0002-nef-akma.patch` before you apply it.

---

## 2. Check the key derivations

AKMA derives three values from the K_AUSF that the 5G primary authentication leaves in the AUSF and in the UE (TS 33.535 Annex A):

- **K_AKMA**, the anchor key, kept by the AAnF;
- **A-TID**, part of the A-KID that the UE presents to the application;
- **K_AF**, the key that the application function (AF) gets from the AAnF.

All three use the KDF of TS 33.220 Annex B.2, the same one that free5GC already uses for K_SEAF.

### 2.1 Run the oracle

```bash
python3 reference/kdf/akma_kdf.py
```

It prints the `S` string and the result of each derivation for a worked example. K_AKMA must be `d6aa856e127fb8de3eb1a1d0cebf52a7df6b69b4a6c68c21c18c1c27d466dbba`.

### 2.2 Test the library against the vectors

```bash
cd shared/akma && go test ./...
```

```bash
cd shared/crosscheck && go test ./...
```

The first compares the Go library with the vectors of the oracle. The second compares it with the KDF of free5GC itself (`free5gc/util`). The vectors are not 3GPP vectors: TS 33.535 publishes none.

### 2.3 Two mistakes that give no error

1. **The SUPI goes into the KDF without the `imsi-` prefix.** free5GC carries `imsi-208930000000001`; the KDF uses `208930000000001` (TS 33.501 A.7.0). With the prefix, every key comes out wrong.
2. **The AF_ID of the KDF is not the `afId` of the API.** The API carries `af1.akma.example.FF00000001`; the KDF uses the FQDN followed by the five raw octets `FF 00 00 00 01` (TS 33.535 A.4).

Both are in `shared/akma/testdata/vectors.json`, under `counterexamples`, with the wrong result each one produces.

### 2.4 A mistake that only shows for some subscribers

The Routing Indicator is a string of 1 to 4 digits where every digit counts: `"0000"`, `"012"` and `"12"` are different values (TS 23.003 cl. 2.2B). Storing it as a number drops the leading zeros and breaks the A-KID of the subscribers whose RID starts with zero. The UERANSIM UE uses `"0000"`.

---

## 3. Install the AAnF

The AAnF (AKMA Anchor Function) keeps the anchor key K_AKMA of each subscriber and hands K_AF to each authorized application (TS 33.535 cl. 4.2.1). free5GC has no such NF. This part adds one, with the layout of the other NFs, **without changing any file of free5GC**: a binary in `bin/` and a configuration in `config/`. Details in [aanf.md](aanf.md).

In this part the AAnF does not get keys from the AUSF yet; that is part 4. It is tested with the `seed` tool, which plays the AUSF and the AF.

### 3.1 Prepare `openapi` and build

`free5gc/openapi` v1.2.4 has no data types for the Naanf_AKMA service. Two patches add them to a local copy of the module, without touching the Go module cache. The script below prepares that copy and builds the AAnF and `seed` as static binaries in `free5gc/build/bin/`:

```bash
free5gc/scripts/build-aanf.sh
```

To check before installing:

```bash
cd free5gc/aanf && go test ./...
```

### 3.2 Configure

`deploy.sh` (section 3.4) installs `free5gc/config/aanfcfg.yaml` when the free5GC host has none, and never overwrites it afterwards. Edit the file before you deploy, or edit the installed copy, `~/free5gc/config/aanfcfg.yaml`, on the free5GC host. The fields:

- `sbi.registerIPv4` and `sbi.bindingIPv4`: an address of the free5GC host that the AF host can reach. Do not use a `127.0.0.x` loopback unless the AF runs on the same host. Port 8010: the free5GC NFs use 8000, and the NEF uses it on the host address (part 9).
- `nrfUri` and `nrfCertPem`: the same as the other NFs (`http://127.0.0.10:8000`, `cert/nrf.pem`).
- `plmnSupportList`: the PLMN of your network.
- `routingIndicators`: the RIDs of the subscribers, **quoted** (`"0000"`). With an empty list, the AAnF serves any RID.
- `akma.authorizedAfs`: each AF that may ask for K_AF, with its AF_ID (`<FQDN>.<Ua* identifier in 10 hex digits>`) and the source address of the AF.
- `nfInstanceId`: keep a fixed UUID. With OAuth2 on in the NRF, every new ID makes the NRF create one more certificate, `cert/aanf_<ID>.pem`.

### 3.3 Fix the NRF

The NRF of free5GC v4.2.3 has three issues against TS 29.510 that affect the AAnF (fixes F1 to F3 in [free5gc-fixes.md](free5gc-fixes.md)):

- it drops the `aanfInfoList` of the profile;
- it refuses discovery of the `AANF` type;
- it issues tokens without `aud`.

The AAnF requires `aud` in the token. **Without this fix, key registration answers 401.** On the free5GC host, with free5GC stopped and the repository at `~/akma-free5gc`:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh nrf apply
```

The script:

1. applies the three patches of `free5gc/patches/nrf/` to `~/free5gc/NFs/nrf`;
2. keeps the original binary as `bin/nrf.orig`;
3. rebuilds with `make nrf`.

`patch-nf.sh nrf revert` undoes it. After the fix, check that free5GC still works as before: `./run.sh` and the UE registration of the installation test.

### 3.4 Install and start

Copy `free5gc/build/bin/aanf` to `~/free5gc/bin/aanf` and the configuration to `~/free5gc/config/aanfcfg.yaml`. From the AF host, `deploy.sh` does it over SSH and leaves an installed configuration alone:

```bash
free5gc/scripts/deploy.sh user@192.168.16.130
```

`FREE5GC_HOST=user@192.168.16.130` works in place of the argument. If the deploy installed the configuration of the repository without the changes of section 3.2, make them now on the free5GC host. With free5GC running (at least the NRF), start the AAnF on the free5GC host:

```bash
~/akma-free5gc/free5gc/scripts/run-aanf.sh start
```

Or from the AF host:

```bash
ssh user@192.168.16.130 bash -s -- start < free5gc/scripts/run-aanf.sh
```

The log goes to `~/free5gc/log/aanf/aanf.log`. Look for `OAuth2 setting receive from NRF: true` and `Start SBI server (listen on …:8010)`. `run-aanf.sh stop` stops the AAnF, which deregisters from the NRF first.

### 3.5 Check registration and discovery at the NRF

```bash
mongosh --quiet free5gc --eval 'printjson(db.NfProfile.find({nfType: "AANF"}, {_id: 0}).toArray())'
```

The profile must have `nfType: 'AANF'`, the `naanf-akma` service (version `v1`) on the configured address, and `aanfInfoList` with the RIDs. To check discovery, run on the free5GC host the `seed` that `deploy.sh` left in `~/akma-tools/`, outside the `PATH`:

```bash
~/akma-tools/seed discover --nrf http://127.0.0.10:8000 --routing-indicator 0000
```

The AAnF must be in the list. With a RID it does not serve, the answer is `null`. This is how the AUSF finds it in part 4 (TS 33.535 cl. 6.7).

### 3.6 Test the three operations

The values below are those of the `testbed-ue` vector (`shared/akma/testdata/vectors.json`). `seed` needs an OAuth2 token to register, and the NRF is only reachable on the free5GC host. To get the token, `seed` registers at the NRF as a temporary AF and deregisters on exit. `--aanf` is the address of the AAnF: the `sbi.registerIPv4` of section 3.2, port 8010.

On the free5GC host, in the role of the AUSF:

```bash
~/akma-tools/seed register --nrf http://127.0.0.10:8000 --aanf http://192.168.16.130:8010 --supi imsi-208930000000001 --k-ausf 141ef548f86e3a2a1ad949331caa9e6bb12401afa321bde4f9f23b84870dd654 --rid 0000 --mcc 208 --mnc 93
```

The output must show the A-KID `rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org`.

On the AF host, whose address has to be in `authorizedAfs`, in the role of the AF, with the `seed` of section 3.1:

```bash
free5gc/build/bin/seed retrieve --aanf http://192.168.16.130:8010 --af-id af1.akma.example.FF00000001 --akid 'rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org'
```

K_AF must be `00c16845c2e4e1256755b84bb06d94e2e659d8ba53c59e874fc149bffd5ea04b`, the one the oracle of part 2 computes. `expiry` must be one hour ahead, in UTC.

Answers that point to a configuration problem:

| Answer | Likely cause |
|---|---|
| `401` on `register` | no `--nrf`; the NRF without the fix of section 3.3 (token without `aud`); or the `nrfCertPem` of the AAnF is not the certificate of the running NRF |
| `403` without cause on `retrieve` | the AF_ID is not in `authorizedAfs`, or the request came from an address that is not in the list of that AF_ID |
| `403 (K_AKMA_NOT_PRESENT)` | the A-KID was not registered, was replaced by a newer registration of the same SUPI, or the AAnF restarted (contexts live in memory) |
| `connection refused` | `--aanf` missing or pointing to another host |

Last, remove the context, on the free5GC host:

```bash
~/akma-tools/seed remove --nrf http://127.0.0.10:8000 --aanf http://192.168.16.130:8010 --supi imsi-208930000000001
```

---

## 4. Enable AKMA in the UDM and the AUSF; provision a subscriber

After a successful primary authentication of a subscriber with an AKMA subscription:

- the UDM tells the AUSF that the UE uses AKMA and gives its Routing Indicator;
- the AUSF derives K_AKMA and the A-KID from K_AUSF and registers them at the AAnF of part 3 (TS 33.535 cl. 6.1).

This part patches the UDM and the AUSF of free5GC (fixes F7 and F8 in [free5gc-fixes.md](free5gc-fixes.md)).

### 4.1 Where the repository lives

The patched AUSF depends on code of this repository: the `shared/akma` library and the `openapi` copy of part 3. The patched `go.mod` files point to `~/akma-free5gc` by relative path, so **the repository has to be there, next to `~/free5gc`** (section 1.1). On the free5GC host, prepare the two `openapi` copies, one for the NFs and one for the free5GC test bench:

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh
```

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh ~/akma-free5gc/free5gc/build/openapi-test v1.2.5-0.20260527003827-02dc71b4d94f
```

### 4.2 Apply the patches

With free5GC stopped, patch the UDM and the AUSF. The script keeps the original binaries as `bin/udm.orig` and `bin/ausf.orig` and rebuilds.

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh udm apply
```

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh ausf apply
```

Turn AKMA on in the configuration. The configuration patch adds `akma.enable: true` to `ausfcfg.yaml`, and the AKMA settings of the NEF of part 9 to `nefcfg.yaml`:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh config apply
```

Without `akma.aanfUri`, the AUSF finds the AAnF at the NRF by Routing Indicator, which needs the NRF fix of section 3.3. To use a fixed address, uncomment `aanfUri` in `ausfcfg.yaml` and set it to the address of section 3.2, port 8010.

For the AKMA tests of the test bench (section 4.4), also apply:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh test apply
```

Each of these steps is undone with `revert` in place of `apply`.

### 4.3 Provision a subscriber

The AKMA subscription is two attributes of the subscriber in the UDR (TS 29.505 table 5.4.2.2-1): `akmaAllowed` and `routingId`. `routingId` is the Routing Indicator of the SUCI of the UE, as a string: `"0000"` for the UERANSIM UE. The web console has no such fields and drops them when you edit the subscriber (fix F9). Provision with the script:

```bash
~/akma-free5gc/free5gc/scripts/provision-akma-subscriber.sh imsi-208930000000001 0000
```

`provision-akma-subscriber.sh imsi-208930000000001 --revoke` takes the subscription away. Run the script again after editing the subscriber in the web console.

### 4.4 Check

**With the free5GC test bench**, with free5GC stopped and without `sudo`:

```bash
cd ~/free5gc/test && go test -v -count=1 -run TestAkma .
```

Three tests must pass:

- `TestAkma5GAKA` and `TestAkmaEAPAKAPrime`: the test UE derives K_AF from its own K_AUSF, and it equals the one the AAnF hands out;
- `TestAkmaWithoutSubscription`: without the subscription, nothing is registered.

**With UERANSIM.** Start free5GC (`./run.sh`), the AAnF (`~/akma-free5gc/free5gc/scripts/run-aanf.sh start`), the gNB and the UE. The free5GC log must show `AKMA key material of imsi-208930000000001 registered at the AAnF`. The AAnF log (`~/free5gc/log/aanf/aanf.log`) shows the stored A-KID, in the form `rid0000.atid<44 characters>@5gc.mnc093.mcc208.3gppnetwork.org`. Part 5 puts all of it on one screen.

If the UERANSIM UE stays in `MM-DEREGISTERED/LIMITED-SERVICE` right after it starts, restart the UE. It is a race in the cell selection of UERANSIM ("no SI"), unrelated to AKMA.

If the AAnF is down, the UE registers anyway and the AUSF only logs the failure: AKMA does not hold up the primary authentication.

---

## 5. AKMA in the logs of free5GC and UERANSIM

Up to here AKMA only showed in the log files. This part does two things:

- the AKMA events show in the terminal of `run.sh`, in the format of the other NFs, with the AAnF in the same terminal;
- the UERANSIM UE derives K_AKMA and the A-KID and shows the A-KID.

That way you can follow the same UE on both screens.

### 5.1 free5GC

The UDM and AUSF patches of part 4 already log the AKMA events. What is left is the `-aanf` option of `run.sh`, with free5GC stopped:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh run apply
```

If the AAnF is running from `run-aanf.sh`, stop it: both would use the same port.

```bash
~/akma-free5gc/free5gc/scripts/run-aanf.sh stop
```

From now on, start free5GC like this:

```bash
cd ~/free5gc && ./run.sh -aanf
```

The AAnF shows on the same screen, with a start line that tells what it serves:

```
[INFO][AANF][AKMA] Routing Indicators [0000]; K_AF lifetime 1h0m0s; AF_IDs authorized by local policy: [af1.akma.example.FF00000001]
```

### 5.2 UERANSIM

On the UERANSIM host, apply the UE patches. The script keeps `build/nr-ue.orig` and rebuilds `nr-ue` and the self-test `nr-akma-selftest`; the first time takes a few minutes.

```bash
~/akma-free5gc/af/scripts/patch-ueransim.sh apply
```

The patches change two things in `config/free5gc-ue.yaml`:

- they turn on the option `akma: true`;
- they make the UE look for the gNB at 10.100.0.1.

If you use another configuration file, do the same there.

10.100.0.1 is the host side of a `veth` pair that links the host to the network namespace of the UE. With UERANSIM and free5GC on the same host, the UE needs that namespace for the PDU session to work: in the host namespace, the address of the PDU session would be local to the host, and the kernel would drop the packets that the UPF delivers. Make the gNB listen there, and create the namespace once per boot:

```bash
sed -i 's/^linkIp: 127.0.0.1 /linkIp: 10.100.0.1 /' ~/UERANSIM/config/free5gc-gnb.yaml
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh up
```

From now on, the UE runs in the namespace:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ue
```

### 5.3 What to look for

Start the gNB as in part 4 and the UE with `ue-netns.sh ue`. On the UE screen, right after `Security Mode Command received`:

```
[nas] [info] AKMA key material derived, A-KID[rid0000.atid<44 characters>@5gc.mnc093.mcc208.3gppnetwork.org]
```

On the `run.sh` screen, the lines with `[AKMA]`, in this order:

1. `[UDM][AKMA] AKMA indication sent to the AUSF for imsi-…, Routing Indicator 0000`;
2. `[AUSF][AKMA] AKMA indication received from the UDM …`;
3. `[AUSF][AKMA] K_AKMA and A-KID derived for imsi-…: A-KID …`;
4. `[AUSF][AKMA] AAnF for Routing Indicator 0000: http://… (discovered at the NRF)`;
5. `[AANF][AKMA] AKMA context of imsi-… registered, A-KID …`;
6. `[AUSF][AKMA] AKMA key material of imsi-… registered at the AAnF`.

The A-KID must be the same, character by character, on the UE screen and in lines 3 and 5. At each new authentication the UE and the network move to a new A-KID together, and the AAnF adds `(previous context replaced)`.

When an AF asks for K_AF (part 6), the AAnF shows `K_AF of imsi-… provided to AF_ID … for A-KID …, expires …`. An AF outside the policy shows as a `WARN`.

No key shows on either screen. In the log file the same messages are in `key=value` form; to filter them:

```bash
grep 'CAT="AKMA"' ~/free5gc/log/<date>/free5gc.log
```

To go back: `patch-nf.sh run revert` and `patch-ueransim.sh revert`.

---

## 6. Run the test AF

An AF that uses AKMA does three things (TS 33.535 cl. 6.2.1):

- it gets the A-KID from the UE;
- it asks the AAnF for the K_AF of that A-KID for its own AF_ID;
- it uses K_AF to authenticate the UE.

The test AF does this with a simplified Ua\*: the HTTP Digest of TS 24.109 K.2 without TLS, with the private-range Ua\* identifier `FF00000001`. The protocol is described in [ua-star.md](ua-star.md).

### 6.1 Authorize the AF at the AAnF

The AAnF only hands K_AF to an authorized AF_ID, from the address of the AF. The `aanfcfg.yaml` of part 3 already has:

```yaml
configuration:
  akma:
    authorizedAfs:
      - afId: af1.akma.example.FF00000001
        sourceAddresses:
          - 192.168.16.129
```

The AF_ID is the FQDN of the AF followed by the Ua\* identifier (TS 33.535 A.4). If you change the FQDN or the AF host, change it here too.

### 6.2 Build and configure the AF

On the AF host, with Go 1.26.2:

```bash
af/scripts/build-af.sh
```

The configuration is `af/config/afcfg.yaml`. The fields that matter:

- `fqdn`: the name by which the UE calls the AF. It goes into K_AF, and the AF only accepts that name in the `Host` header.
- `listen`: the address the AF listens on. Requests to the AAnF do not leave from it: they leave from the address the system picks for the route to the AAnF, and that one has to be in `sourceAddresses` (section 6.1). On a host with a single interface, the two are the same.
- `aanfUri`: the address of the AAnF, the `sbi.registerIPv4` of section 3.2 with port 8010.
- `kafExpiry`: what to do when K_AF expires, `refetch` or `reject`.

```bash
af/build/bin/af -c af/config/afcfg.yaml
```

The start line shows the AF_ID and the `realm`:

```
[INFO][AF][Main] AF_ID af1.akma.example.FF00000001; realm "3GPP-bootstrapping-akma@af1.akma.example"; ...
```

### 6.3 Test without a UE

The UERANSIM UE only hands out K_AF in part 7. Before that, play the UE with a test vector, in two steps:

1. seed the AAnF with the context of the `testbed-ue` vector, as in section 3.6 (`~/akma-tools/seed register`, with `--aanf`);
2. run the Ua\* client with the same vector:

   ```bash
   af/build/bin/uaclient -vector testbed-ue -n 3
   ```

The client asks for the session, gets the challenge, answers with the A-KID and K_AF, and checks the `rspauth` of the AF:

```
session established (nc 00000001): AF authenticated by rspauth; K_AF valid until ...
```

The AF shows `K_AF for A-KID … obtained from the AAnF` and `UE with A-KID … authenticated`. The AAnF shows `K_AF of imsi-… provided to AF_ID af1.akma.example.FF00000001`.

What to try next, and what to expect:

| Case | Answer of the AF |
|---|---|
| wrong K_AF: `-akid` with the A-KID of the vector and `-kaf` with another value (`-kaf` is ignored with `-vector`) | `401` |
| an A-KID the AAnF does not know (`-vector rid-012`) | `403 AKMA_KEY_NOT_AVAILABLE` |
| another name in `Host` (`-vector testbed-ue -fqdn af2.akma.example`) | `421 MISDIRECTED_REQUEST` |
| AF_ID outside the policy of the AAnF: a second AF with `fqdn: af2.akma.example` and another port in `listen`; the client with `-vector testbed-ue -fqdn af2.akma.example -connect <listen of that AF>` | `503 AANF_UNAVAILABLE` |

**Before part 7.** The `testbed-ue` vector has the SUPI of the UERANSIM UE (`imsi-208930000000001`). If the UE has already registered, the `seed register` of this test replaced its context at the AAnF. Run a new authentication of the UE (section 7.4) before section 7.3. Otherwise the AF answers `403 AKMA_KEY_NOT_AVAILABLE` to the UE, because the AAnF no longer has the A-KID the UE presents.

### 6.4 Limitations

Without TLS, the A-KID and the content travel in clear, and the AF is only authenticated by `rspauth`. It is a protocol for test beds; see [ua-star.md](ua-star.md).

---

## 7. Prepare the UE for Ua\*

In part 5 the UE started to derive K_AKMA and the A-KID. Now it also derives the K_AF of an AF and hands it to an application, which reaches the AF over the PDU session (TS 33.535 cl. 6.2.1 step 1).

### 7.1 Open the user plane

With the UE in the namespace of part 5, the free5GC host still needs NAT on N6. It brings the answers of the AF, or of the Internet, back to the UE. It is not persistent: run it again after a reboot.

```bash
sudo ~/akma-free5gc/free5gc/scripts/n6-nat.sh apply
```

With free5GC, the gNB and the UE up, the UE must reach the AF and the Internet through `uesimtun0`:

```bash
sudo ip netns exec ueransim-ue ping -I uesimtun0 -c 3 192.168.16.129
```

### 7.2 Check the derivations of the UE

The self-test compares the derivations of the UE with the test vectors of part 2:

```bash
~/UERANSIM/build/nr-akma-selftest ~/akma-free5gc/shared/akma/testdata/vectors.json
```

Expected: `5 passed, 3 refused (FQDN not ASCII), 0 failed`. The three refused vectors have a non-ASCII FQDN, for which the UE derives no K_AF, because it does not apply NFKC.

### 7.3 Authenticate at the AF from the UE

On the UERANSIM host, build the Ua\* client with `~/akma-free5gc/af/scripts/build-af.sh`, or copy `af/build/bin/uaclient` from the AF host to the same place. The AAnF must have the context of the last authentication of the UE: if section 6.3 seeded the `testbed-ue` vector after the UE registered, run the new authentication of section 7.4 first. With the AF of part 6 up:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -n 3
```

The client runs in the namespace of the UE, as your user:

- it asks the UE, through `nr-cli`, for the A-KID and the K_AF of `af1.akma.example`;
- it goes to the AF from the address of the PDU session;
- it checks `rspauth`.

```
ME: K_AF derived for AF_ID af1.akma.example.FF00000001
AF af1.akma.example at 192.168.16.129:8080 from 10.60.0.1, A-KID rid0000.atid…
session established (nc 00000001): AF authenticated by rspauth; K_AF valid until …
```

The same A-KID shows on the screens of the UE, of free5GC (AUSF and AAnF) and of the AF. The UE screen also shows `[app] [info] AKMA K_AF derived for AF_ID[af1.akma.example.FF00000001], …`.

### 7.4 New authentication

Force a new primary authentication:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh cli imsi-208930000000001 -e "deregister normal"
```

The UE registers again by itself, with a new authentication. What changes:

- the UE and the network derive a new A-KID;
- the AAnF logs `(previous context replaced)`;
- the Ua\* client uses the new A-KID;
- a K_AF request with the old A-KID gets `403 K_AKMA_NOT_PRESENT` from the AAnF.

### 7.5 Limitations

`nr-cli` is a test interface: it hands the K_AF of any AF to any local process. K_AKMA never leaves the UE (TS 33.535 cl. 4.4.3).

---

## 8. End-to-end run

With parts 3 to 7 and section 9.1 done, one script runs all of AKMA and the negative tests on both hosts, and writes a report. Details in [testing.md](testing.md).

### 8.1 Prepare

On the AF host:

```bash
af/scripts/build-af.sh
```

```bash
free5gc/scripts/build-aanf.sh
```

The AF host needs SSH with a key to the free5GC host (section 1.1) and the `af/config/afcfg.yaml` of section 6.2. On the free5GC host, the script expects what the previous parts left:

- the repository at `~/akma-free5gc`;
- the patches applied, the AAnF deployed and `seed` in `~/akma-tools/`;
- UERANSIM with the patches and `linkIp: 10.100.0.1`;
- `uaclient` in `~/akma-free5gc/af/build/bin/`.

The script also checks the NEF path of part 9, so do section 9.1 first: the patched NEF, the configuration patch and `akma.authorizedNefs` in the AAnF. Without them, the NEF checks fail.

free5GC must be stopped: the script starts it. Stop your own AFs too, and close the tunnel of section 9.2: the script starts its own AFs on ports 8080 to 8085 of the `listen` address and its own tunnel to the NRF.

### 8.2 Run

On the AF host, with the user and address of the free5GC host:

```bash
af/scripts/e2e.sh user@192.168.16.130
```

`FREE5GC_HOST=user@192.168.16.130` works in place of the argument. The address of the AAnF comes from `aanfUri` in `af/config/afcfg.yaml`. Before it starts, the script checks that it is the `sbi.bindingIPv4` of the `aanfcfg.yaml` installed on the free5GC host.

The script asks once for the `sudo` password of the free5GC host and takes about two minutes. It:

- applies the N6 NAT and creates the namespace of the UE;
- starts free5GC with the AAnF, the gNB and the UE;
- authenticates the UE at the AF;
- forces new primary authentications: with the AAnF down, without the AKMA subscription and with it restored;
- runs the negative tests;
- stops everything.

Each check prints `PASS` or `FAIL`, and the end shows the total:

```
report: …/af/build/e2e/<date-time>/report.md
83 passed, 0 failed
```

### 8.3 Read the report

`report.md` has the A-KID of each authentication, the table of checks, and the AKMA lines of free5GC, of the UE and of the AF. It lets you follow the whole chain:

1. **Primary authentication and registration.** The UE authenticates; the UDM signals AKMA; the AUSF derives the A-KID and registers it at the AAnF.
2. **Same A-KID.** The UE derived the same A-KID.
3. **Ua\*.** The AF gets K_AF from the AAnF and authenticates the UE with it, and the UE checks the `rspauth` of the AF.

---

## 9. AF outside the operator network, anonymous access, context removal

Up to here the AF sat inside the operator network and asked the AAnF directly. This part shows:

- an AF outside the network asking the NEF for K_AF (TS 33.535 cl. 6.3);
- anonymous access, where the AF gets K_AF without the SUPI (cl. 6.2.2);
- the removal of the AKMA context (cl. 6.6).

The API is described in [nef-akma-api.md](nef-akma-api.md).

### 9.1 Prepare the NEF

The NEF of free5GC has no AKMA API. With free5GC stopped, on the free5GC host:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh nef apply
```

The patch adds `POST /3gpp-akma/v1/retrieve` (TS 29.522 cl. 5.14) to the NEF and rebuilds it; the original binary stays as `bin/nef.orig`.

The configuration of the NEF comes from the configuration patch of part 4 (`free5gc/patches/config/0002-nef-akma.patch`). In `~/free5gc/config/nefcfg.yaml`, check:

- `sbi.registerIPv4` and `sbi.bindingIPv4`: the address of the free5GC host, which the external AF can reach. The port stays 8000;
- `3gpp-akma` in `serviceList`;
- `akma.authorizedAfs`: each external AF_ID, with the source address of the AF (cl. 6.3 step 2).

The patch also authorizes `af3.akma.example.FF00000001`, which the AAnF does not accept. It is there for a negative test of part 8; remove it outside a test bed.

The AAnF has to accept requests that come through the NEF. In `~/free5gc/config/aanfcfg.yaml`, `akma.authorizedNefs` gives the address of the NEF and the external AF_IDs accepted from it ([aanf.md](aanf.md), section 5).

Start free5GC with `./run.sh -aanf`. The NEF shows `Start SBI server (listen on 192.168.16.130:8000)`; the AAnF shows `AF_IDs accepted from a NEF: [af1.akma.example.FF00000001]`.

### 9.2 Run the AF outside the operator network

The external AF registers at the NRF to get the access token of the NEF API: free5GC has no CAPIF, and its NEF accepts tokens issued by the NRF. The NRF listens on a loopback address of the free5GC host, so the AF reaches it through an SSH tunnel. On the AF host, keep the tunnel open in a terminal:

```bash
ssh -N -L 127.0.0.10:8000:127.0.0.10:8000 user@192.168.16.130
```

The configuration of the external AF is `af/config/afcfg-external.yaml`. It has `nefUri` in place of `aanfUri`, plus `nrfUri` and port 8083. In another terminal:

```bash
af/build/bin/af -c af/config/afcfg-external.yaml
```

The AF shows:

```
[INFO][AF][Main] AF outside the operator network: K_AF through the NEF at http://192.168.16.130:8000; registered at the NRF http://127.0.0.10:8000 as AF … (OAuth2 true)
```

With the UE up (part 7), authenticate the UE at the external AF:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -connect 192.168.16.129:8083 -n 3
```

The output of the client is that of section 7.3. The free5GC screen shows the lines of the NEF and of the AAnF:

```
[INFO][NEF][AKMA] K_AF request from AF_ID af1.akma.example.FF00000001 for A-KID rid0000.atid…
[INFO][AANF][AKMA] K_AF of imsi-208930000000001 provided to AF_ID af1.akma.example.FF00000001 for A-KID …, through the NEF at 192.168.16.130
[INFO][NEF][AKMA] K_AF for A-KID rid0000.atid… relayed to AF_ID af1.akma.example.FF00000001, expires …
```

The NEF lines do not show the SUPI, and neither does the answer of the NEF to the AF (cl. 6.3 step 5).

On Ctrl-C the AF deregisters from the NRF.

### 9.3 Anonymous access

With `anonymous: true` in the configuration, the AF asks for K_AF with `anonInd` and gets only K_AF and its expiry, without the SUPI (cl. 6.2.2). It works for the internal and the external AF. The AF uses the A-KID as a temporary user identifier.

On the NEF screen the anonymous request shows as `K_AF request … , anonymous`. The AAnF still knows whose context it is: the anonymity is towards the AF.

### 9.4 Remove the context at the AAnF

The consumer of context removal in the specification is the OAM (TS 29.535 cl. 4.2.1.3.2 and table 4.2.2.1-1). Here `seed` plays that role, on the free5GC host:

```bash
~/akma-tools/seed remove --nrf http://127.0.0.10:8000 --aanf http://192.168.16.130:8010 --supi imsi-208930000000001
```

The answer is `removed`. From then on, the AF gets `403 AKMA_KEY_NOT_AVAILABLE` until a new primary authentication of the UE (section 7.4).

---

## 10. UERANSIM on another host

The free5GC guide installs UERANSIM on a separate host. In the example topology: free5GC on 192.168.16.130, the AF on 192.168.16.129 and UERANSIM on 192.168.16.131.

**On the free5GC host**, N2 and N3 move from the loopback to the host address, as the free5GC guide says:

| File | Field | Value |
|---|---|---|
| `config/amfcfg.yaml` | `ngapIpList` | `192.168.16.130` |
| `config/smfcfg.yaml` | `endpoints` of the N3 interface of the UPF | `192.168.16.130` |
| `config/upfcfg.yaml` | `gtpu.ifList[].addr` | `192.168.16.130` |

If the free5GC host still runs a gNB, it needs two changes in `free5gc-gnb.yaml`:

- `ngapIp`: the host address. A gNB on the loopback does not reach the AMF on 192.168.16.130 (`Network is unreachable`);
- `gtpIp`: `10.100.0.1`, the address of the `veth` of the namespace. It cannot be `127.0.0.1`, for the same reason, and it cannot be the host address, because port 2152 of that address belongs to the UPF.

**On the UERANSIM host**, follow parts 5 and 7 with the repository at `~/akma-free5gc`: the UERANSIM patches, the namespace of the UE and `uaclient`. In `config/free5gc-gnb.yaml`:

| Field | Value |
|---|---|
| `linkIp` | `10.100.0.1` |
| `ngapIp`, `gtpIp` | the address of the UERANSIM host, `192.168.16.131` |
| `amfConfigs[].address` | the address of the free5GC host, `192.168.16.130` |

The N6 NAT stays on the free5GC host; the UERANSIM host needs no NAT. On the UERANSIM host, one terminal per command:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh up
```

```bash
~/UERANSIM/build/nr-gnb -c ~/UERANSIM/config/free5gc-gnb.yaml
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ue
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -n 3
```

The gNB shows `SCTP connection established (192.168.16.130:38412)` and `NG Setup procedure is successful`. The UE shows the A-KID, which is the same in the AUSF and AAnF lines on the free5GC screen. For the external AF, use `ua -connect 192.168.16.129:8083`.

`e2e.sh` expects the gNB and the UE on the free5GC host.

---

## 11. Undo

Everything above is undone in reverse order, with free5GC stopped:

```bash
~/akma-free5gc/free5gc/scripts/run-aanf.sh stop
```

```bash
for nf in nef test run config ausf udm nrf; do ~/akma-free5gc/free5gc/scripts/patch-nf.sh $nf revert; done
```

```bash
~/akma-free5gc/af/scripts/patch-ueransim.sh revert
```

```bash
sudo ~/akma-free5gc/free5gc/scripts/n6-nat.sh remove
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh down
```

```bash
~/akma-free5gc/free5gc/scripts/provision-akma-subscriber.sh imsi-208930000000001 --revoke
```

`revert` restores the original binaries from `bin/<nf>.orig`. `bin/aanf`, `config/aanfcfg.yaml` and `~/akma-tools/` are new files: remove them by hand. The `linkIp` of the gNB and the N2 and N3 changes of part 10 are manual too.

To move to a newer version of the patches, revert with the old version first: `patch-nf.sh` and `patch-ueransim.sh` reverse exactly the patches they find in the repository.
