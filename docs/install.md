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
| 11 | Refresh K_AKMA: the AAnF asks for a new authentication |
| 12 | Upgrading from V1 |
| 13 | Undo |

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
| `af/config/afcfg.yaml` (section 6.2) | `listen` of each profile, `aanfUri` |
| `af/config/afcfg-external.yaml` (section 9.2) | `listen` of each profile, `nefUri` |
| `seed` | `--aanf`, default `http://192.168.16.130:8010` |
| `uaclient` | `-connect`, default `192.168.16.129` with the port of the profile |
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
[INFO][AANF][AKMA] Routing Indicators [0000]; K_AF lifetime 1h0m0s; AF_IDs authorized by local policy: [af1.akma.example.0100000007 af1.akma.example.0100011301 …]
```

### 5.2 UERANSIM

On the UERANSIM host, apply the UE patches. The script keeps `build/nr-ue.orig` and rebuilds `nr-ue` and the self-test `nr-akma-selftest`; the first time takes a few minutes.

```bash
~/akma-free5gc/af/scripts/patch-ueransim.sh apply
```

The patches change three things in `config/free5gc-ue.yaml`:

- they turn on the option `akma: true`;
- they make the UE look for the gNB at 10.100.0.1;
- they add the policy of the AKMA key service of the ME, which gives an application only the K_AF of its own AF_IDs (TS 33.535 cl. 4.4.3):

  ```yaml
  akmaKeyService:
    applications:
      - name: uaclient
        uid: 1000            # the user that runs the application
        afIds:             # one per Ua* profile and cipher suite (TS 33.220 H.3)
          - af1.akma.example.0100011301   # Digest in TLS 1.3 (K.2)
          - af1.akma.example.0100011302
          - af1.akma.example.0100011303
          - af1.akma.example.010001C02B   # Digest in TLS 1.2
          - af1.akma.example.010001C02C
          - af1.akma.example.0100000007   # TLS 1.3 with K_AF as pre-shared key (K.3.3)
          - af1.akma.example.010001D001   # (D)TLS 1.2 with K_AF as pre-shared key (K.3.2)
          - af1.akma.example.0100000009   # DTLS 1.3 with K_AF as pre-shared key (TS 33.535 Annex C)
          - af1.akma.example.0100000008   # OSCORE with a context from K_AF (TS 33.535 Annex D)
          - af1.akma.example.FF00000001   # simplified Ua*, test only
  akmaCliKaf: false
  ```

If the user that runs the Ua\* client is not uid 1000 (`id -u`), change `uid`. If you use another configuration file, do the same there. `executable`, optional, also ties the application to the absolute path of its executable. An AF_ID given to two applications makes `nr-ue` refuse the configuration.

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

The test AF serves the Ua\* profiles of TS 24.109 Annex K, each on its own port:

| Profile | Port in the example | How the UE authenticates | AF_ID |
|---|---|---|---|
| `digest-tls` (K.2) | 8443 | HTTP Digest keyed with K_AF inside TLS; the AF authenticates with its certificate | `<FQDN>.010001<cipher suite>` |
| `psk-tls13` (K.3.3) | 8444 | TLS 1.3 with K_AF as external pre-shared key | `<FQDN>.0100000007` |
| `psk-tls12` (K.3.2) | 8445 | TLS 1.2 `ECDHE-PSK` with K_AF | `<FQDN>.010001D001` |
| `psk-dtls13` (TS 33.535 Annex C) | UDP 5684 | DTLS 1.3 with K_AF as pre-shared key; CoAP inside | `<FQDN>.0100000009` |
| `psk-dtls12` | UDP 5685 | DTLS 1.2 `ECDHE-PSK` with K_AF; CoAP inside | `<FQDN>.010001D001` |
| `oscore` (TS 33.535 Annex D) | UDP 5683 | CoAP protected by OSCORE, with a context derived from K_AF | `<FQDN>.0100000008` |
| `digest-http` (test, off by default) | 8080 | the simplified Ua\*: the Digest without TLS ([ua-star.md](ua-star.md)) | `<FQDN>.FF00000001` |

### 6.1 Authorize the AF at the AAnF

The AAnF only hands K_AF to an authorized AF_ID, from the address of the AF. Each profile, and in K.2 each cipher suite, has its own AF_ID (TS 33.220 H.3). The `aanfcfg.yaml` of part 3 already has the ten AF_IDs of `af1.akma.example`:

```yaml
configuration:
  akma:
    authorizedAfs:
      - afId: af1.akma.example.0100011301   # K.2 in TLS 1.3, TLS_AES_128_GCM_SHA256
        sourceAddresses:
          - 192.168.16.129
      # ... 0100011302, 0100011303, 010001C02B, 010001C02C (K.2),
      #     0100000007 (PSK TLS 1.3), 010001D001 (PSK TLS and DTLS 1.2),
      #     0100000009 (PSK DTLS 1.3), 0100000008 (OSCORE), FF00000001 (test)
```

The AF_ID is the FQDN of the AF followed by the Ua\* identifier (TS 33.535 A.4). If you change the FQDN or the AF host, change every entry.

### 6.2 Build and configure the AF

On the AF host, with Go 1.26.2, `gcc`, `make` and `unzip`. First wolfSSL, for the PSK profiles: Go's `crypto/tls` has neither the PSK cipher suites of TS 33.210 nor DTLS. The script downloads wolfSSL 5.9.4, checks its SHA-256 and builds it in `af/build/wolfssl`:

```bash
af/scripts/build-wolfssl.sh
```

Then a test CA and the certificate of the AF for K.2, in `af/build/cert`:

```bash
af/scripts/make-test-ca.sh
```

And the AF and the client:

```bash
af/scripts/build-af.sh
```

Linked with wolfSSL, the binaries are licensed under the GPL v3, like wolfSSL. Without it (`AF_WOLFSSL=no`), the AF has no PSK profiles and refuses to start with one in its configuration.

The configuration is `af/config/afcfg.yaml`. The fields that matter:

- `fqdn`: the name by which the UE calls the AF. It goes into K_AF, and the AF only accepts that name in the `Host` header and in the TLS `server_name`.
- `profiles`: one server per profile, with `type` and `listen`; `digest-tls` also has `certificate` and `key`, relative to the file. Requests to the AAnF do not leave from the `listen` addresses: they leave from the address the system picks for the route to the AAnF, and that one has to be in `sourceAddresses` (section 6.1). On a host with a single interface, they are the same.
- `aanfUri`: the address of the AAnF, the `sbi.registerIPv4` of section 3.2 with port 8010.
- `kafExpiry`: what to do when K_AF expires, `refetch` or `reject`. In the PSK profiles the AF also ends the TLS session when K_AF expires.

```bash
af/build/bin/af -c af/config/afcfg.yaml
```

The start lines show each profile:

```
[INFO][AF][Main] Built with wolfSSL: PSK profiles available
[INFO][AF][Main] Ua* server digest-tls listening on 192.168.16.129:8443 for https://af1.akma.example/ua/v1/session, AF_ID af1.akma.example.010001<cipher suite> (TS 24.109 K.2)
[INFO][AF][Main] Ua* server psk-tls13 listening on 192.168.16.129:8444 for https://af1.akma.example/ua/v1/session, AF_ID af1.akma.example.0100000007 (TS 24.109 K.3.3)
[INFO][AF][Main] Ua* server psk-tls12 listening on 192.168.16.129:8445 for https://af1.akma.example/ua/v1/session, AF_ID af1.akma.example.010001<cipher suite> (TS 24.109 K.3.2)
```

### 6.3 Test without a UE

The UERANSIM UE only hands out K_AF in part 7, and it derives it for any profile. Before that, play the UE with a test vector. A vector carries the K_AF of one AF_ID only, `af1.akma.example.FF00000001`, the one of the test profile. Turn it on by uncommenting these lines of `af/config/afcfg.yaml`, and restart the AF:

```yaml
    - type: digest-http
      listen: 192.168.16.129:8080
```

Then:

1. seed the AAnF with the context of the `testbed-ue` vector, as in section 3.6 (`~/akma-tools/seed register`, with `--aanf`);
2. run the Ua\* client with the same vector:

   ```bash
   af/build/bin/uaclient -vector testbed-ue -n 3
   ```

The client asks for the session, gets the challenge, answers with the A-KID and K_AF, and checks the `rspauth` of the AF:

```
session established (nc 00000001): AF authenticated by rspauth; A-KID …; AF_ID af1.akma.example.FF00000001; K_AF valid until ...
```

The AF shows `K_AF for A-KID … and AF_ID af1.akma.example.FF00000001 obtained from the AAnF` and `UE with A-KID … authenticated`. The AAnF shows `K_AF of imsi-… provided to AF_ID af1.akma.example.FF00000001`.

What to try next, and what to expect:

| Case | Answer of the AF |
|---|---|
| wrong K_AF: `-akid` with the A-KID of the vector and `-kaf` with another value (`-kaf` is ignored with `-vector`) | `401` |
| an A-KID the AAnF does not know (`-vector rid-012`) | `403 AKMA_KEY_NOT_AVAILABLE` |
| another name in `Host` (`-vector testbed-ue -fqdn af2.akma.example`) | `421 MISDIRECTED_REQUEST` |
| AF_ID outside the policy of the AAnF: a second AF with `fqdn: af2.akma.example` and other ports; the client with `-vector testbed-ue -fqdn af2.akma.example -connect <listen of that AF>` | `503 AANF_UNAVAILABLE` |
| a certificate of another name in K.2: `-profile digest-tls -ca af/build/cert/ca.pem -vector testbed-ue -fqdn af2.akma.example` | the client ends the TLS before sending the A-KID |
| PSK with the K_AF of another AF_ID: `-profile psk-tls13 -vector testbed-ue` | the handshake fails |

Turn `digest-http` off again after the test.

**Before part 7.** The `testbed-ue` vector has the SUPI of the UERANSIM UE (`imsi-208930000000001`). If the UE has already registered, the `seed register` of this test replaced its context at the AAnF. Run a new authentication of the UE (section 7.4) before section 7.3. Otherwise the AF refuses the UE, because the AAnF no longer has the A-KID the UE presents.

### 6.4 Limitations

- **`digest-http`.** Without TLS, the A-KID and the content travel in clear, and the AF is only authenticated by `rspauth` ([ua-star.md](ua-star.md)). Test only.
- **Certificate.** The certificate of K.2 comes from a test CA, without revocation or OCSP.
- **SBI.** The request of the AF to the AAnF still has no TLS.

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

On the UERANSIM host, put the Ua\* client and the test CA of the AF where the script looks for them: copy `af/build/bin/uaclient` from the AF host to `~/akma-free5gc/af/build/bin/` and `af/build/cert/ca.pem` to `~/akma-free5gc/af/build/cert/`. The client built on the AF host is static and runs on the UERANSIM host. The AAnF must have the context of the last authentication of the UE: if section 6.3 seeded the `testbed-ue` vector after the UE registered, run the new authentication of section 7.4 first. With the AF of part 6 up:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-tls13 -n 2
```

The client runs in the namespace of the UE, as your user:

- it asks the AKMA key service of the ME, on `/run/ueransim/akma-<SUPI>.sock`, for the A-KID and the K_AF of the AF_ID of the profile;
- it goes to the AF from the address of the PDU session;
- in TLS 1.3 with a pre-shared key, the handshake authenticates both sides with K_AF.

```
AF af1.akma.example at 192.168.16.129:8444 from 10.60.0.1, profile psk-tls13
ME: K_AF derived for AF_ID af1.akma.example.0100000007
session established: AF authenticated by the TLS handshake with K_AF; A-KID rid0000.atid…; AF_ID af1.akma.example.0100000007; TLS 1.3, cipher suite 1301; K_AF valid until …
```

The other profiles:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-tls12 -reconnect -n 2
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile digest-tls -ca ~/akma-free5gc/af/build/cert/ca.pem -n 3
```

And the DTLS profiles, with CoAP over UDP through the PDU session:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-dtls13 -reconnect -n 2
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-dtls12 -reconnect -n 2
```

And the OSCORE profile: one `POST /akma` and two protected requests in the same context; with `-rekey`, the context is renewed before each request:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile oscore -n 2
```

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile oscore -rekey -n 2
```

In TLS 1.2, the ME derives K_AF after the AF has picked the cipher suite (`AF_ID af1.akma.example.010001D001`), and with `-reconnect` the second connection resumes the session (`resumed true`). In DTLS 1.3 the AF_ID is `af1.akma.example.0100000009`; the AF answers the first ClientHello with a cookie and asks the AAnF for K_AF only once the UE sends it back. In K.2, the client checks the certificate of the AF against `af1.akma.example` and the CA, and runs the Digest inside TLS; the AF_ID carries the cipher suite of the connection, such as `af1.akma.example.0100011301`.

The same A-KID shows on the screens of the UE, of free5GC (AUSF and AAnF) and of the AF. The UE screen also shows `K_AF for AF_ID[af1.akma.example.0100000007] given to application [uaclient] (uid 1000), …`.

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

The key service tells applications apart by user. The executable in the policy is a best-effort check: a process of the same user can replace or inject into an application. K_AKMA never leaves the UE (TS 33.535 cl. 4.4.3).

`nr-cli akma-kaf` also gives the K_AF of any AF, but only with `akmaCliKaf: true`, for tests: it answers any local process.

---

## 8. End-to-end run

With parts 3 to 7 and section 9.1 done, one script runs all of AKMA and the negative tests on both hosts, and writes a report. Details in [testing.md](testing.md).

### 8.1 Prepare

On the AF host:

```bash
af/scripts/build-wolfssl.sh
```

```bash
af/scripts/make-test-ca.sh
```

```bash
af/scripts/build-af.sh
```

```bash
free5gc/scripts/build-aanf.sh
```

The AF host needs SSH with a key to the free5GC host (section 1.1), `openssl`, and the `af/config/afcfg.yaml` of section 6.2. On the free5GC host, the script expects what the previous parts left:

- the repository at `~/akma-free5gc`;
- the patches applied, the AAnF deployed and `seed` in `~/akma-tools/`;
- UERANSIM with the patches and `linkIp: 10.100.0.1`;
- `uaclient` built with wolfSSL in `~/akma-free5gc/af/build/bin/` (section 7.3).

The script runs its own AF with the profiles of `afcfg.yaml` plus `digest-http` on port 8080, and copies the test CA to the free5GC host.

The script also checks the NEF path of part 9, so do section 9.1 first: the patched NEF, the configuration patch and `akma.authorizedNefs` in the AAnF. Without them, the NEF checks fail.

free5GC must be stopped: the script starts it. Stop your own AFs too, and close the tunnel of section 9.2: the script starts its own AFs on TCP ports 8080 to 8085, 8443 to 8448 and 8456 and UDP ports 5683 to 5685, 5687 and 5688 of the address of the first `listen`, and its own tunnel to the NRF.

### 8.2 Run

On the AF host, with the user and address of the free5GC host:

```bash
af/scripts/e2e.sh user@192.168.16.130
```

`FREE5GC_HOST=user@192.168.16.130` works in place of the argument. The address of the AAnF comes from `aanfUri` in `af/config/afcfg.yaml`. Before it starts, the script checks that it is the `sbi.bindingIPv4` of the `aanfcfg.yaml` installed on the free5GC host.

The script asks once for the `sudo` password of the free5GC host and takes about four minutes. It:

- applies the N6 NAT and creates the namespace of the UE;
- starts free5GC with the AAnF, the gNB and the UE;
- authenticates the UE at the AF over every profile: K.2 in TLS 1.3 and 1.2, PSK in TLS 1.3 and 1.2, PSK in DTLS 1.3 and 1.2 with CoAP, and OSCORE, with session resumption and context renewal;
- checks PSK TLS 1.3 with `openssl s_client` as the UE, and the expiry of K_AF in a TLS session; with an OpenSSL 4.1 in `OPENSSL_DTLS13`, it also checks PSK DTLS 1.3, and with libcoap in `LIBCOAP_CLIENT`, OSCORE ([testing.md](testing.md) section 5.1);
- forces new primary authentications: with the AAnF down, without the AKMA subscription and with it restored;
- refreshes K_AKMA through the AAnF, with `kakmaRefresh: 20s`: the UDM notifies the AMF, which re-authenticates the registered UE (part 11);
- runs the negative tests;
- stops everything.

Each check prints `PASS` or `FAIL`, and the end shows the total:

```
report: …/af/build/e2e/<date-time>/report.md
161 passed, 0 failed, 0 skipped
```

Without `OPENSSL_DTLS13`, check D03 is reported as skipped; without `LIBCOAP_CLIENT`, checks O04 and O05. Without both: `158 passed, 0 failed, 3 skipped`.

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
- `akma.authorizedAfs`: each external AF_ID, with the source address of the AF (cl. 6.3 step 2): the same ten AF_IDs of `af1.akma.example` as the AAnF.

The patch also authorizes `af3.akma.example.FF00000001`, which the AAnF does not accept. It is there for a negative test of part 8; remove it outside a test bed.

The AAnF has to accept requests that come through the NEF. In `~/free5gc/config/aanfcfg.yaml`, `akma.authorizedNefs` gives the address of the NEF and the external AF_IDs accepted from it ([aanf.md](aanf.md), section 5).

Start free5GC with `./run.sh -aanf`. The NEF shows `Start SBI server (listen on 192.168.16.130:8000)`; the AAnF shows `AF_IDs accepted from a NEF: [af1.akma.example.0100000007 af1.akma.example.0100011301 …]`.

### 9.2 Run the AF outside the operator network

The external AF registers at the NRF to get the access token of the NEF API: free5GC has no CAPIF, and its NEF accepts tokens issued by the NRF. The NRF listens on a loopback address of the free5GC host, so the AF reaches it through an SSH tunnel. On the AF host, keep the tunnel open in a terminal:

```bash
ssh -N -L 127.0.0.10:8000:127.0.0.10:8000 user@192.168.16.130
```

The configuration of the external AF is `af/config/afcfg-external.yaml`. It has `nefUri` in place of `aanfUri`, plus `nrfUri`, and the same profiles as the internal AF on TCP ports 8453 to 8455 and UDP ports 5693 to 5695. In another terminal:

```bash
af/build/bin/af -c af/config/afcfg-external.yaml
```

The AF shows:

```
[INFO][AF][Main] AF outside the operator network: K_AF through the NEF at http://192.168.16.130:8000; registered at the NRF http://127.0.0.10:8000 as AF … (OAuth2 true)
```

With the UE up (part 7), authenticate the UE at the external AF:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-tls13 -connect 192.168.16.129:8454 -n 1
```

The output of the client is that of section 7.3. The free5GC screen shows the lines of the NEF and of the AAnF:

```
[INFO][NEF][AKMA] K_AF request from AF_ID af1.akma.example.0100000007 for A-KID rid0000.atid…
[INFO][AANF][AKMA] K_AF of imsi-208930000000001 provided to AF_ID af1.akma.example.0100000007 for A-KID …, through the NEF at 192.168.16.130
[INFO][NEF][AKMA] K_AF for A-KID rid0000.atid… relayed to AF_ID af1.akma.example.0100000007, expires …
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
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-tls13 -n 2
```

The gNB shows `SCTP connection established (192.168.16.130:38412)` and `NG Setup procedure is successful`. The UE shows the A-KID, which is the same in the AUSF and AAnF lines on the free5GC screen. For the external AF, use `ua -profile psk-tls13 -connect 192.168.16.129:8454`.

`e2e.sh` expects the gNB and the UE on the free5GC host.

---

## 11. Refresh K_AKMA: the AAnF asks for a new authentication

K_AKMA only changes with a new primary authentication (TS 33.535 cl. 6.4.1). By the local policy of the operator, the AAnF may ask the UDM for one (cl. 6.4.4): the UDM notifies the AMF, the AMF authenticates the registered UE again, and the AUSF registers the new K_AKMA and A-KID at the AAnF. The UE derives its own at the Security Mode Command the AMF sends next. Nothing changes in the UERANSIM UE.

free5GC has none of this chain. This part applies the patches of the UDM, the AMF and `openapi` ([free5gc-fixes.md](free5gc-fixes.md), F16 to F19) and turns on the policy of the AAnF ([aanf.md](aanf.md) section 8).

### 11.1 Update `openapi` and the UDM, fix the AMF

On the free5GC host, with free5GC stopped, prepare both `openapi` copies again (section 4.1); the script applies every patch up to `0003`:

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh
```

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh ~/akma-free5gc/free5gc/build/openapi-test v1.2.5-0.20260527003827-02dc71b4d94f
```

If you did part 4 with this version of the repository, the UDM already has both patches (`patch-nf.sh udm status` says `patches applied`). With an older version it only has `0001`, and `apply` refuses the local changes. Revert with a copy of `0001` and apply again:

```bash
mkdir -p ~/udm-0001 && cp ~/akma-free5gc/free5gc/patches/udm/0001-*.patch ~/udm-0001/
```

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh udm revert ~/udm-0001
```

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh udm apply
```

Then the AMF. The script keeps `bin/amf.orig` and rebuilds:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh amf apply
```

### 11.2 Turn on the policy of the AAnF

Build and install the AAnF and `seed` again (sections 3.1 and 3.4):

```bash
free5gc/scripts/build-aanf.sh
```

```bash
free5gc/scripts/deploy.sh user@free5gc-host
```

`deploy.sh` keeps the installed configuration. Add to the `akma` block of `~/free5gc/config/aanfcfg.yaml` the age after which the AAnF asks for the refresh:

```yaml
  akma:
    kakmaRefresh: 1m
```

`0`, or no line, turns it off. With a value, when an AF asks for the K_AF of a K_AKMA registered longer ago, the AAnF hands out the K_AF and asks the UDM for the refresh in the background, once per K_AKMA, and again after 5 minutes if the K_AKMA did not change. One minute is enough to watch it; in a real network the value is the authentication policy of the operator.

### 11.3 Watch the refresh

Start free5GC with the AAnF (`./run.sh -aanf`, part 5), the gNB and the UE in its namespace (part 7). Wait one minute after the UE registers, then run a Ua\* with an AF_ID the AF has not used yet with this A-KID; the AF keeps each K_AF until it expires and would not ask the AAnF again:

```bash
sudo ~/akma-free5gc/af/scripts/ue-netns.sh ua -profile psk-tls13 -n 1
```

The AF gets the K_AF, and the console of free5GC shows the chain: the AAnF (`K_AKMA of <SUPI> registered <age> ago: refresh requested from the UDM`), the UDM (`AuthTrigger for <SUPI> from AANF at <address>: re-authentication notified to the AMF <id>`), the AMF (`Re-authentication of <SUPI> requested by the UDM: started`), the AUSF with the new A-KID, the AMF again (`completed, new KAMF in use`) and the AAnF (`AKMA context of <SUPI> registered, A-KID <new A-KID> (previous context replaced)`). The UE prints `AKMA key material derived, A-KID[...]` with the same new A-KID. The PDU session goes on: the next Ua\* goes through the same `uesimtun0`, with the new A-KID. The AF still accepts the previous K_AF until it expires (TS 33.535 cl. 6.4.2).

### 11.4 Ask for the refresh by hand

`seed` sends the same request as the AAnF, without waiting for the policy. On the free5GC host:

```bash
~/akma-tools/seed trigger-auth --nrf http://127.0.0.10:8000 --supi imsi-208930000000001
```

It prints `accepted (204)`. A second request for the same SUPI within 60 s gets `UDM answered 403 (REAUTHENTICATION_NOT_ALLOWED; ...)`: that is the policy of the UDM (TS 33.501 cl. 6.1.5.2, NOTE A).

### 11.5 Limitations

- 3GPP access only, and no AS re-keying, which is optional (TS 33.501 cl. 6.9.4.4): UERANSIM has no AS security.
- A UE in CM-IDLE (answer `202` and a pending authentication) is only covered by the unit tests of the AMF: UERANSIM does not stay in CM-IDLE.
- After a restart of the UDM, the request gets `404 CONTEXT_NOT_FOUND` until the UE registers again: the UDR of free5GC does not keep the notification address of the AMF.

---

## 12. Upgrading from V1

For a host that runs V1 of this repository. Between V1 and V2, one patch changed (`free5gc/patches/config/0002`) and four are new (`openapi/0003`, `udm/0002`, `amf/0001`, UERANSIM `0005`); the patches of the NRF, AUSF, NEF, `run.sh` and test bench are the same. `patch-nf.sh` and `patch-ueransim.sh` reverse exactly the patches they find, so the changed sets are reverted with the V1 copies first.

### 12.1 free5GC host

With free5GC and the AAnF stopped, keep a copy of the V1 patches before updating the clone:

```bash
cp -r ~/akma-free5gc/free5gc/patches ~/akma-v1-patches && cp -r ~/akma-free5gc/af/ue/ueransim/patches ~/akma-v1-ueransim-patches
```

Revert the configuration, the UDM and UERANSIM with them:

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh config revert ~/akma-v1-patches/config
```

```bash
~/akma-free5gc/free5gc/scripts/patch-nf.sh udm revert ~/akma-v1-patches/udm
```

```bash
~/akma-free5gc/af/scripts/patch-ueransim.sh revert ~/akma-v1-ueransim-patches
```

Update the clone to V2 and prepare both `openapi` copies again (section 4.1):

```bash
cd ~/akma-free5gc && git pull
```

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh
```

```bash
~/akma-free5gc/free5gc/scripts/prepare-openapi.sh ~/akma-free5gc/free5gc/build/openapi-test v1.2.5-0.20260527003827-02dc71b4d94f
```

Apply the new and changed sets:

```bash
for nf in config udm amf; do ~/akma-free5gc/free5gc/scripts/patch-nf.sh $nf apply; done
```

```bash
~/akma-free5gc/af/scripts/patch-ueransim.sh apply
```

The UERANSIM patch `0005` adds the key service of the ME and its policy to `free5gc-ue.yaml` (part 7). With UERANSIM on another host (part 10), run the two UERANSIM commands there, with the V1 copy of its patches.

### 12.2 AAnF

Build and install the AAnF and `seed` again (sections 3.1 and 3.4). `deploy.sh` keeps the installed `aanfcfg.yaml`. V2 adds, in the `akma` block, one AF_ID per Ua\* profile in `authorizedAfs` and `authorizedNefs`, and `kakmaRefresh` (part 11). Copy them from `free5gc/config/aanfcfg.yaml`, or replace the file with `deploy.sh --force-config`, which shows the differences, and set your addresses again (section 1.2).

### 12.3 AF host

Update the clone, then build wolfSSL, the test CA and the AF (part 6):

```bash
af/scripts/build-wolfssl.sh && af/scripts/make-test-ca.sh && af/scripts/build-af.sh
```

`af/config/afcfg.yaml` has one listener per Ua\* profile; set your addresses again. Then run `af/scripts/e2e.sh` (part 8): `161 passed, 0 failed`.

## 13. Undo

Everything above is undone in reverse order, with free5GC stopped:

```bash
~/akma-free5gc/free5gc/scripts/run-aanf.sh stop
```

```bash
for nf in nef test run config amf ausf udm nrf; do ~/akma-free5gc/free5gc/scripts/patch-nf.sh $nf revert; done
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
