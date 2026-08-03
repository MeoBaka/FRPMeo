<template>
  <div class="firewall-page" v-loading="loading">
    <div class="page-head">
      <div>
        <h1 class="page-title">Firewall</h1>
        <p class="page-subtitle">
          Native access control by source IP and destination port. Order: manual rules -> reputation provider
          (optional) -> default policy. frps queries the provider; it does not
          host a blocklist itself.
        </p>
      </div>
      <div class="enable-box">
        <span>Enabled</span>
        <el-switch v-model="snap.enabled" @change="save" />
      </div>
    </div>

    <!-- Scope -->
    <el-card class="section" shadow="never">
      <div class="card-title">Scope</div>
      <p class="hint">
        Rules match the source IP and the frps port it connects to (tcp, udp,
        http, https, mc, pe, tcpmux, tcp+udp). A port belongs to one proxy at a
        time, so a rule survives a proxy being re-registered under a new name.
        Note that http / https proxies share the vhost port and mc proxies may
        share a port, so a rule there covers all of them. stcp / xtcp and their
        udp variants are visitor-authenticated and are not covered.
      </p>
      <div class="fg-inline" style="margin-top:12px">
        <label>Also protect the frps control port</label>
        <el-switch v-model="snap.controlPort" @change="save" />
        <span class="hint">
          Applies rules to frpc clients connecting to bindPort, before login -
          name that port in a rule to block a client from logging in. Careful:
          with default policy "deny" this locks out every client that has no
          explicit allow rule.
        </span>
      </div>

      <div class="fg-inline" style="margin-top:12px">
        <label>Also protect this dashboard</label>
        <el-switch v-model="snap.webPort" @change="save" />
        <span class="hint">
          Applies rules to webServer.port, on accept and so before the TLS
          handshake. Careful: this page is what edits these rules, so a rule or
          default policy that blocks the port can only be undone by editing
          frps_firewall.json on the server and restarting frps.
        </span>
      </div>
    </el-card>

    <!-- Reputation provider -->
    <el-card class="section" shadow="never">
      <div class="card-title">Blacklist provider (for unknown IPs)</div>
      <div class="bar">
        <el-select v-model="snap.provider.mode" class="w220">
          <el-option label="Off (rules + default only)" value="off" />
          <el-option label="FRPControl" value="frpcontrol" />
          <el-option label="Custom API" value="custom" />
        </el-select>
        <span class="hint">frps asks this API whether an unknown source IP is blacklisted (cached).</span>
      </div>

      <!-- FRPControl: only URL + key -->
      <div v-if="snap.provider.mode === 'frpcontrol'" class="field-grid">
        <div class="fg-wide">
          <label>FRPControl URL (base)</label>
          <el-input v-model="snap.provider.frpControlURL" placeholder="https://frpcontrol.example.com:7002" />
        </div>
        <div class="fg-wide">
          <label>API key</label>
          <el-input v-model="snap.provider.frpControlAPIKey" placeholder="fwk_xxx" show-password />
        </div>
        <p class="hint fg-wide">frps calls POST {url}/api/fw/check with header X-API-Key and reads results.0.blacklisted.</p>
      </div>

      <!-- Custom -->
      <div v-else-if="snap.provider.mode === 'custom'" class="field-grid">
        <div class="fg-wide">
          <label>URL ({ip} placeholder)</label>
          <el-input v-model="snap.provider.url" placeholder="https://host/api/check?ip={ip}" />
        </div>
        <div>
          <label>Method</label>
          <el-select v-model="snap.provider.method" class="w120">
            <el-option label="GET" value="GET" /><el-option label="POST" value="POST" />
          </el-select>
        </div>
        <div v-if="snap.provider.method === 'POST'" class="fg-wide">
          <label>POST body ({ip})</label>
          <el-input v-model="snap.provider.body" placeholder='{"ips":["{ip}"]}' />
        </div>
        <div class="fg-wide">
          <label>Headers (one "Key: value" per line)</label>
          <el-input v-model="headersText" type="textarea" :rows="2" placeholder="X-API-Key: fwk_xxx" />
        </div>
        <div class="fg-wide">
          <label>Blocked JSON path (dot, supports {ip} + array index)</label>
          <el-input v-model="snap.provider.blockedPath" placeholder="results.0.blacklisted" />
        </div>
      </div>

      <!-- common (frpcontrol / custom) -->
      <div v-if="snap.provider.mode !== 'off'" class="field-grid" style="margin-top:12px">
        <div><label>Cache TTL (s)</label><el-input v-model.number="snap.provider.cacheTTLSec" type="number" placeholder="300" /></div>
        <div><label>Timeout (ms)</label><el-input v-model.number="snap.provider.timeoutMs" type="number" placeholder="800" /></div>
        <div class="fg-inline"><label>Fail-open</label><el-switch v-model="snap.provider.failOpen" /><span class="hint">off = block on error</span></div>
        <div class="fg-inline"><label>Insecure TLS</label><el-switch v-model="snap.provider.insecureTLS" /><span class="hint">self-signed https</span></div>
        <div class="fg-inline fg-wide">
          <label>Wait for the first answer</label>
          <el-switch v-model="snap.provider.blocking" />
          <span class="hint">
            Off by default. The query is an http round trip and the callers are
            accept loops, so waiting means one unknown address delays every
            other client - and an attack is made of unknown addresses. Left off,
            the first connection from a source is judged by the rules and the
            default policy while the lookup runs behind it, and every connection
            after that has the answer.
          </span>
        </div>
      </div>

      <!-- The provider form is free text, so it saves on demand rather than on
           every keystroke. Everything else on this page applies on change. -->
      <div class="bar" style="margin-top:12px">
        <div class="grow" />
        <el-button type="primary" :loading="saving" @click="save">Save provider</el-button>
      </div>
    </el-card>

    <!-- Manual rules -->
    <el-card class="section" shadow="never">
      <div class="bar">
        <div class="field">
          <label>Default policy</label>
          <el-select v-model="snap.default" class="w120" @change="save">
            <el-option label="allow" value="allow" /><el-option label="deny" value="deny" />
          </el-select>
        </div>
        <div class="grow" />
        <span class="hint">Every change here applies immediately.</span>
        <el-button type="primary" @click="openAdd">Add rule</el-button>
      </div>
      <el-table :data="pagedRules" empty-text="No manual rules - provider + default policy apply">
        <el-table-column label="Action" width="90">
          <template #default="{ row }">
            <el-tag :type="row.action === 'allow' ? 'success' : 'danger'" disable-transitions>{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Source" min-width="200">
          <template #default="{ row }">
            <div>{{ row.cidr || 'any' }}</div>
            <div v-if="domainOf(row)" class="hint" style="margin:2px 0 0">
              <span v-if="domainOf(row)!.addresses?.length">-> {{ domainOf(row)!.addresses!.join(', ') }}</span>
              <span v-else>not resolved yet</span>
              <el-tag v-if="domainOf(row)!.error" type="warning" size="small" style="margin-left:6px" :title="domainOf(row)!.error">lookup failing</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Port" min-width="110"><template #default="{ row }">{{ row.port || 'all' }}</template></el-table-column>
        <el-table-column label="Trusted" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.trusted && row.action === 'allow'" type="success" size="small" disable-transitions>trusted</el-tag>
            <span v-else class="hint">-</span>
          </template>
        </el-table-column>
        <el-table-column label="Expires" min-width="110"><template #default="{ row }">{{ expiryText(row.expiresAt) }}</template></el-table-column>
        <el-table-column label="Note" prop="note" min-width="120" />
        <el-table-column label="" width="170" align="right">
          <!-- $index is the row's position on this page; rules are matched in
               order across the whole list, so map it back before touching. -->
          <template #default="{ $index }">
            <el-button size="small" @click="moveUp(rowIndex($index))" :disabled="rowIndex($index) === 0">Up</el-button>
            <el-button size="small" @click="openEdit(rowIndex($index))">Edit</el-button>
            <el-button size="small" type="danger" @click="removeRule(rowIndex($index))">Del</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-if="snap.rules.length > pageSize"
        class="pager"
        layout="total, sizes, prev, pager, next"
        :total="snap.rules.length"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        background
      />
    </el-card>

    <!-- AntiAttacker -->
    <el-card class="section" shadow="never">
      <div class="bar" style="justify-content:space-between">
        <div class="card-title" style="margin:0">AntiAttacker (rate limiting)</div>
        <el-switch v-model="snap.antiAttacker.enabled" @change="save" />
      </div>
      <p class="hint">
        Rules decide who may connect; this decides how often. A source over the
        limit is refused for the rest of the window, and only banned once it goes
        over in several separate windows - so one burst throttles, a sustained
        one blocks. Bans expire on their own and are never extended by retries.
        Off by default: a limit set too low turns real users away.
      </p>
      <p class="hint">
        It cannot drop packets. The kernel has finished the TCP handshake before
        frps is handed the connection, so this makes refusing cheap rather than
        preventing the attempt. frps does not touch the host firewall.
      </p>

      <template v-if="snap.antiAttacker.enabled">
        <p class="hint" style="margin-top:12px">
          Applies to every proxy. Which sources are exempt is a rules question,
          not a second list here: add an allow rule and tick Trusted.
        </p>

        <el-divider content-position="left">TCP - counted per connection</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.tcp.enabled" @change="save" />
          <span class="hint">
            tcp, mc, tcpmux, https and the tcp half of tcp+udp. Refused
            connections are closed with RST, leaving no TIME_WAIT socket
            behind. Not the frps control port: rules still guard that, but it
            is not rate limited. stcp / sudp / xtcp+xudp are exempt too - their
            callers proved a shared secret to get this far, so a limit could
            only throttle a tunnel that is entitled to the traffic.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.tcp.enabled">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.tcp.windowMs" type="number" class="w120" />
          <label class="lbl">Max / window</label>
          <el-input v-model.number="snap.antiAttacker.tcp.maxPerWindow" type="number" class="w90" />
          <label class="lbl">Ban after</label>
          <el-input v-model.number="snap.antiAttacker.tcp.banViolations" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.tcp.banSeconds" type="number" class="w90" />
          <label class="lbl">Per /24 or /48</label>
          <el-input v-model.number="snap.antiAttacker.tcp.subnetMaxPerWindow" type="number" class="w90" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>
        <p class="hint" v-if="snap.antiAttacker.tcp.enabled">
          Defaults 5000 / 4 / 3 / 60 - four attempts per five seconds, banned for
          a minute once three separate windows go over. "Ban after" counts
          windows, not attempts.
        </p>


        <p class="hint" style="margin-top:8px">
          "Per /24 or /48" counts every source in the same block together, and is
          the only tier that sees a botnet rotating through one - each address
          gets a single unremarkable attempt, so per-source counting has nothing
          to look at. It only throttles, never bans: a /24 can be a carrier-grade
          NAT block with a whole town behind it. To block a range outright, write
          a deny rule instead, so it is a decision rather than a counter. Leave
          at 0 to switch the tier off.
        </p>

        <el-divider content-position="left">HTTP - counted per request</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.http.enabled" @change="save" />
          <span class="hint">
            Counted per request, not per connection: the vhost proxy pools work
            connections, so later requests arrive on one admitted long ago.
            Refused with 429 and a Retry-After rather than a dropped connection,
            which browsers read as a network error and retry harder.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.http.enabled">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.http.windowMs" type="number" class="w120" />
          <label class="lbl">Max / window</label>
          <el-input v-model.number="snap.antiAttacker.http.maxPerWindow" type="number" class="w90" />
          <label class="lbl">Ban after</label>
          <el-input v-model.number="snap.antiAttacker.http.banViolations" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.http.banSeconds" type="number" class="w90" />
          <label class="lbl">Retry-After (s)</label>
          <el-input v-model.number="snap.antiAttacker.http.retryAfterSec" type="number" class="w90" placeholder="auto" />
          <label class="lbl">Per /24 or /48</label>
          <el-input v-model.number="snap.antiAttacker.http.subnetMaxPerWindow" type="number" class="w90" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>
        <p class="hint" style="margin-top:12px" v-if="snap.antiAttacker.http.enabled">
          X-Forwarded-For is believed only from a peer covered by an allow rule
          with Trusted ticked - add one naming your load balancer or CDN. From
          anyone else the socket address is counted instead, which behind a CDN
          means every visitor counts as one source, so raise the limit
          accordingly. It is the Trusted tick rather than any allow rule because
          believing the header from a peer you merely allow does not weaken the
          limit, it removes it: the value is written by whoever is calling, so an
          attacker is never the same source twice.
        </p>


        <el-divider content-position="left">Signals - not about volume</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.strikes.enabled" @change="save" />
          <span class="hint">
            A rate limit asks "is this too much traffic". These ask "is this a
            client at all", and that answer is worth far more - an frpc having a
            bad day still speaks frp. A peer that fails the protocol, or that
            keeps connecting and carrying nothing, is banned on the evidence
            rather than on a threshold somebody guessed.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.strikes.enabled">
          <label class="lbl">Protocol failures</label>
          <el-input v-model.number="snap.antiAttacker.strikes.protocolFailures" type="number" class="w90" placeholder="0 = off" />
          <label class="lbl">Empty connections</label>
          <el-input v-model.number="snap.antiAttacker.strikes.emptyConnections" type="number" class="w90" placeholder="0 = off" />
          <label class="lbl">Empty below (bytes)</label>
          <el-input v-model.number="snap.antiAttacker.strikes.emptyBytes" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.strikes.banSeconds" type="number" class="w90" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">Trust - stop measuring people who already behaved</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.trust.enabled" @change="save" />
          <span class="hint">
            This is what makes a tight limit safe to set. A connection that
            lasted and carried real traffic earns its source an exemption, so
            the people who actually use the tunnel stop being measured. Scans
            and floods never qualify: they do not hold a connection open and
            they do not send anything.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.trust.enabled">
          <label class="lbl">After (ms)</label>
          <el-input v-model.number="snap.antiAttacker.trust.afterMs" type="number" class="w120" />
          <label class="lbl">Min bytes</label>
          <el-input v-model.number="snap.antiAttacker.trust.minBytes" type="number" class="w90" />
          <label class="lbl">Trusted for (s)</label>
          <el-input v-model.number="snap.antiAttacker.trust.forSeconds" type="number" class="w120" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">Attack state - when the blunt measures earn their cost</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.attack.enabled" @change="save" />
          <span class="hint">
            Not a defence of its own but the switch the disruptive ones hang
            off. Shortening the handshake timeout frees sockets five times
            faster under a slow flood, and cuts off honest clients on bad links
            if left on permanently - so it only applies while the connection
            rate says an attack is happening.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.attack.enabled">
          <label class="lbl">Connections / sec</label>
          <el-input v-model.number="snap.antiAttacker.attack.connectionsPerSec" type="number" class="w90" />
          <label class="lbl">Cooldown (s)</label>
          <el-input v-model.number="snap.antiAttacker.attack.cooldownSec" type="number" class="w90" />
          <label class="lbl">Handshake timeout (ms)</label>
          <el-input v-model.number="snap.antiAttacker.attack.initialTimeoutMs" type="number" class="w120" placeholder="0 = leave alone" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">Startup grace</el-divider>
        <div class="bar">
          <label class="lbl">Suspend all checks for (s) after frps starts</label>
          <el-input v-model.number="snap.antiAttacker.graceSeconds" type="number" class="w90" />
          <el-button @click="save" :loading="saving">Save</el-button>
          <span class="hint">
            A restart is a burst frps causes itself - every frpc reconnects at
            once, each opening a login and a pool of work connections. Without
            this the first thing a fresh server can do is ban the clients it
            exists to serve.
          </span>
        </div>

        <el-divider content-position="left">Control port - counted per connection</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.control.protect" @change="save" />
          <span class="hint">
            The frps control port (bindPort). Its own switch, and its own much
            looser limits, because an frpc client's work connections arrive on
            this port too: one healthy client is a login plus poolCount
            connections at startup and more as the pool refills. Refusing one
            keeps its tunnels down until it gets back in, so raise these rather
            than trim them.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.control.protect">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.control.windowMs" type="number" class="w120" />
          <label class="lbl">Max / window</label>
          <el-input v-model.number="snap.antiAttacker.control.maxPerWindow" type="number" class="w90" />
          <label class="lbl">Ban after</label>
          <el-input v-model.number="snap.antiAttacker.control.banViolations" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.control.banSeconds" type="number" class="w90" />
          <label class="lbl">Per /24 or /48</label>
          <el-input v-model.number="snap.antiAttacker.control.subnetMaxPerWindow" type="number" class="w90" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">Dashboard port - counted per connection</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.web.protect" @change="save" />
          <span class="hint">
            This page's own port. Rules only stop addresses somebody thought to
            list, so this is the layer that answers password guessing. Careful:
            this page is what edits these settings, and a limit set very low can
            lock you out until frps_firewall.json is edited on the server. The
            default leaves room for a page load, which opens several connections
            for its assets before anyone types anything.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.web.protect">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.web.windowMs" type="number" class="w120" />
          <label class="lbl">Max / window</label>
          <el-input v-model.number="snap.antiAttacker.web.maxPerWindow" type="number" class="w90" />
          <label class="lbl">Ban after</label>
          <el-input v-model.number="snap.antiAttacker.web.banViolations" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.web.banSeconds" type="number" class="w90" />
          <label class="lbl">Per /24 or /48</label>
          <el-input v-model.number="snap.antiAttacker.web.subnetMaxPerWindow" type="number" class="w90" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">SSH gateway port - counted per connection</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.ssh.protect" @change="save" />
          <span class="hint">
            The ssh tunnel gateway, when one is configured. One client is one
            ssh session here - the tunnelled data travels over an internal
            listener, not this port - so the limit can be far tighter than the
            control port's.
          </span>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.ssh.protect">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.ssh.windowMs" type="number" class="w120" />
          <label class="lbl">Max / window</label>
          <el-input v-model.number="snap.antiAttacker.ssh.maxPerWindow" type="number" class="w90" />
          <label class="lbl">Ban after</label>
          <el-input v-model.number="snap.antiAttacker.ssh.banViolations" type="number" class="w90" />
          <label class="lbl">Ban (s)</label>
          <el-input v-model.number="snap.antiAttacker.ssh.banSeconds" type="number" class="w90" />
          <label class="lbl">Per /24 or /48</label>
          <el-input v-model.number="snap.antiAttacker.ssh.subnetMaxPerWindow" type="number" class="w90" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>

        <el-divider content-position="left">UDP - counted per packet</el-divider>
        <div class="bar">
          <el-switch v-model="snap.antiAttacker.udp.enabled" @change="save" />
          <span class="hint">
            udp and pe (Minecraft Bedrock), plus the udp half of tcp+udp. A
            refused packet is dropped in silence - UDP has no way to say no.
          </span>
        </div>
        <p class="hint" v-if="snap.antiAttacker.udp.enabled" style="margin-top:8px">
          No ban here, by design. UDP has no handshake, so a source address is
          whatever the sender wrote: banning one would let an attacker get any
          address blocked just by forging it. Per-source limits are still worth
          having against ordinary floods, but only the global ceilings hold when
          the source is forged. A zero means that limit is off.
        </p>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.udp.enabled">
          <label class="lbl">Window (ms)</label>
          <el-input v-model.number="snap.antiAttacker.udp.windowMs" type="number" class="w120" />
          <label class="lbl">Packets / window</label>
          <el-input v-model.number="snap.antiAttacker.udp.maxPacketsPerWindow" type="number" class="w90" />
          <label class="lbl">Bytes / window</label>
          <el-input v-model.number="snap.antiAttacker.udp.maxBytesPerWindow" type="number" class="w120" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>
        <div class="bar" style="margin-top:8px" v-if="snap.antiAttacker.udp.enabled">
          <label class="lbl">Global packets / window</label>
          <el-input v-model.number="snap.antiAttacker.udp.globalMaxPacketsPerWindow" type="number" class="w120" placeholder="0 = off" />
          <label class="lbl">Global bytes / window</label>
          <el-input v-model.number="snap.antiAttacker.udp.globalMaxBytesPerWindow" type="number" class="w120" placeholder="0 = off" />
          <span class="hint">
            Counted across every source together, and off by default because the
            right number is whatever this host can carry. Once reached
            everything is dropped, real traffic included: it bounds the damage
            rather than telling good from bad.
          </span>
        </div>
      </template>
    </el-card>


    <!-- Live status -->
    <el-card class="section" shadow="never" v-if="snap.antiAttacker.enabled">
      <div class="bar" style="justify-content:space-between">
        <div class="card-title" style="margin:0">Currently blocking</div>
        <div class="bar">
          <el-tag v-if="status.inGrace" type="warning" disable-transitions>startup grace</el-tag>
          <el-tag v-if="status.underAttack" type="danger" disable-transitions>under attack</el-tag>
          <el-button size="small" @click="loadStatus" :loading="statusLoading">Refresh</el-button>
          <el-button size="small" type="danger" @click="clearBans" :disabled="!status.bans.length">Lift all bans</el-button>
        </div>
      </div>
      <p class="hint">
        Everything above is deliberately quiet - a refusal writes no log line,
        since a flood being turned away must not become a flood of writes. This
        is how to tell a working configuration from one that is off, and who is
        being turned away.
      </p>
      <div class="bar" style="margin-top:8px">
        <span class="hint">Trusted sources: {{ status.trusted }}</span>
        <span class="hint">Open connections tracked: {{ status.openConns }}</span>
        <span class="hint" v-for="(n, k) in status.tracked" :key="k">{{ k }}: {{ n }}</span>
      </div>
      <el-table :data="status.bans" style="margin-top:12px" empty-text="Nothing is being blocked right now">
        <el-table-column label="Source" prop="source" min-width="150" />
        <el-table-column label="Layer" prop="tier" width="110" />
        <el-table-column label="Reason" prop="reason" min-width="140" />
        <el-table-column label="Ends in" width="110">
          <template #default="{ row }">{{ row.secondsLeft }}s</template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Add/Edit rule dialog -->
    <el-dialog v-model="dialog.open" :title="dialog.index === -1 ? 'Add rule' : 'Edit rule'" width="480px">
      <el-form label-width="100px">
        <el-form-item label="Action">
          <el-select v-model="dialog.rule.action"><el-option label="allow" value="allow" /><el-option label="deny" value="deny" /></el-select>
        </el-form-item>
        <el-form-item label="Source">
          <el-input v-model="dialog.rule.cidr" placeholder="1.2.3.0/24, ::1, 1.2.3.4, office.example.com (blank=any)" />
          <div class="hint" style="margin-top:4px">
            An address, a CIDR block, or a domain name. A domain is resolved in
            the background and looked up again on an interval, so a rule can
            name a connection whose address moves - a home line on dynamic DNS,
            say - and keep meaning the same thing. It works either way round:
            allow follows the name in, deny follows it out.
          </div>
        </el-form-item>
        <el-form-item v-if="dialog.rule.action === 'allow'" label="Trusted">
          <el-switch v-model="dialog.rule.trusted" />
          <div class="hint" style="margin-top:4px">
            Off by default. On, a source this rule matches is also exempt from
            the rate limits, the bans and the reputation provider - not just
            from the rules. Turn it on for the addresses you cannot afford to
            have locked out by a counter, and keep the list short: it does turn
            every other layer off for them.
          </div>
        </el-form-item>
        <el-form-item label="Port">
          <el-input v-model="dialog.rule.port" placeholder="all" />
          <div class="hint" style="margin-top:4px">
            The frps port the client connects to: a single port (6000), a lo-hi
            range (6000-6010), a list (80,443,7000-7010), or all. Left blank it
            becomes all.
          </div>
        </el-form-item>
        <el-form-item label="Duration">
          <el-select v-model="dialog.duration" class="w160">
            <el-option label="Permanent" value="perm" /><el-option label="14 days" value="14" /><el-option label="Custom days" value="custom" />
          </el-select>
          <el-input v-if="dialog.duration === 'custom'" v-model.number="dialog.days" type="number" class="w90" style="margin-left:8px" />
        </el-form-item>
        <el-form-item label="Note"><el-input v-model="dialog.rule.note" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog.open = false">Cancel</el-button>
        <el-button type="primary" @click="applyDialog">OK</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { http } from '../api/http'

// cidr is an address, a CIDR block or a domain name. trusted only means
// anything on an allow rule: it exempts the source from the rate limits, the
// bans and the reputation provider as well as from the rules.
interface Rule { id?: string; action: string; cidr: string; port: string; trusted?: boolean; note: string; expiresAt?: number }
interface Provider {
  mode: string
  frpControlURL: string; frpControlAPIKey: string
  url: string; method: string; body: string; headers: Record<string, string>; blockedPath: string
  cacheTTLSec: number; timeoutMs: number; failOpen: boolean; insecureTLS: boolean; blocking: boolean
}
interface RateProfile {
  enabled: boolean
  windowMs: number; maxPerWindow: number; banViolations: number; banSeconds: number
  idleForgetMs: number; maxTracked: number
  // 0 = off. Counts every source in the same /24 (or /48) together, which is
  // the only tier that sees a botnet rotating through a block.
  subnetMaxPerWindow: number
  globalMaxPerWindow: number
  maxConcurrent: number
}
interface HTTPProfile extends RateProfile { retryAfterSec: number }
// UDP is its own shape: two dimensions, a global tier, and no ban - a forged
// source address makes banning a weapon rather than a defence.
interface UDPProfile {
  enabled: boolean
  windowMs: number
  maxPacketsPerWindow: number; maxBytesPerWindow: number
  globalMaxPacketsPerWindow: number; globalMaxBytesPerWindow: number
  idleForgetMs: number; maxTracked: number
}
// Control carries its own Protect switch: enabling AntiAttacker for proxies
// must never start refusing the frpc clients that keep the tunnels up.
interface ControlProfile extends RateProfile { protect: boolean }
interface AntiAttacker {
  enabled: boolean
  tcp: RateProfile; http: HTTPProfile; udp: UDPProfile
  // Three separate doors into frps, three budgets: hammering one must not
  // spend another's.
  control: ControlProfile; web: ControlProfile; ssh: ControlProfile
  graceSeconds: number
  attack: { enabled: boolean; connectionsPerSec: number; cooldownSec: number; initialTimeoutMs: number }
  trust: { enabled: boolean; afterMs: number; minBytes: number; forSeconds: number; maxTracked: number }
  strikes: {
    enabled: boolean; protocolFailures: number; emptyConnections: number
    emptyBytes: number; banSeconds: number; forgetMs: number; maxTracked: number
  }
}
// What a rule's domain currently resolves to. A name that stopped resolving is
// still matching its old addresses, which has to be visible.
interface DomainStatus {
  domain: string
  addresses?: string[]
  resolvedSecondsAgo?: number
  error?: string
}

interface BanEntry { source: string; tier: string; reason: string; secondsLeft: number }
interface FwStatus {
  underAttack: boolean; inGrace: boolean
  tracked: Record<string, number>; trusted: number; openConns: number; bans: BanEntry[]
}
interface Snap {
  enabled: boolean; controlPort: boolean; webPort: boolean; default: string
  rules: Rule[]; provider: Provider; antiAttacker: AntiAttacker; domainRefreshSec: number
}

function defProvider(): Provider {
  return { mode: 'off', frpControlURL: '', frpControlAPIKey: '', url: '', method: 'GET', body: '', headers: {}, blockedPath: '', cacheTTLSec: 300, timeoutMs: 800, failOpen: false, insecureTLS: false, blocking: false }
}

// Defaults mirror the server's. The tcp numbers come from XCord's speedy-login
// settings; the http ones are sized so an ordinary page load cannot trip them.
function defAntiAttacker(): AntiAttacker {
  return {
    enabled: false,
    // Both profiles ship enabled so that turning the feature on does something.
    // The master switch above is what keeps it off until asked for.
    tcp: { enabled: true, windowMs: 5000, maxPerWindow: 4, banViolations: 3, banSeconds: 60, idleForgetMs: 40000, maxTracked: 65536, subnetMaxPerWindow: 0, globalMaxPerWindow: 0, maxConcurrent: 0 },
    http: { enabled: true, windowMs: 10000, maxPerWindow: 120, banViolations: 5, banSeconds: 120, idleForgetMs: 60000, maxTracked: 65536, subnetMaxPerWindow: 0, globalMaxPerWindow: 0, maxConcurrent: 0, retryAfterSec: 0 },
    // Per-source rates from XCord's during-login anti-ddos settings. The global
    // ceilings stay at zero: no default can guess a host's capacity.
    udp: { enabled: true, windowMs: 1000, maxPacketsPerWindow: 500, maxBytesPerWindow: 50000, globalMaxPacketsPerWindow: 0, globalMaxBytesPerWindow: 0, idleForgetMs: 30000, maxTracked: 65536 },
    // Far looser than tcp: a frpc pool is many connections from one address.
    control: { protect: false, enabled: true, windowMs: 5000, maxPerWindow: 200, banViolations: 3, banSeconds: 60, idleForgetMs: 40000, maxTracked: 65536, subnetMaxPerWindow: 0, globalMaxPerWindow: 0, maxConcurrent: 0 },
    // Tighter than control - a login form, not a pool - with a long ban, since
    // nothing legitimate trips it.
    web: { protect: false, enabled: true, windowMs: 5000, maxPerWindow: 60, banViolations: 3, banSeconds: 300, idleForgetMs: 60000, maxTracked: 65536, subnetMaxPerWindow: 0, globalMaxPerWindow: 0, maxConcurrent: 0 },
    graceSeconds: 60,
    // Off by default, every one of them: each costs something when wrong, and
    // none should start acting because somebody flipped the master switch.
    attack: { enabled: false, connectionsPerSec: 40, cooldownSec: 60, initialTimeoutMs: 2000 },
    trust: { enabled: false, afterMs: 300000, minBytes: 4096, forSeconds: 86400, maxTracked: 65536 },
    strikes: { enabled: false, protocolFailures: 3, emptyConnections: 6, emptyBytes: 64, banSeconds: 600, forgetMs: 3600000, maxTracked: 65536 },
    ssh: { protect: false, enabled: true, windowMs: 5000, maxPerWindow: 10, banViolations: 3, banSeconds: 300, idleForgetMs: 60000, maxTracked: 65536, subnetMaxPerWindow: 0, globalMaxPerWindow: 0, maxConcurrent: 0 },
  }
}

const loading = ref(false)
const saving = ref(false)
const statusLoading = ref(false)

// Live state, refreshed on demand rather than polled: it is a diagnostic, and a
// timer on every open dashboard would be its own small flood.
const status = reactive<FwStatus>({
  underAttack: false, inGrace: false, tracked: {}, trusted: 0, openConns: 0, bans: [],
})

async function loadStatus() {
  statusLoading.value = true
  try {
    const s = await http.get<FwStatus>('../api/firewall/status')
    status.underAttack = !!s.underAttack
    status.inGrace = !!s.inGrace
    status.tracked = s.tracked || {}
    status.trusted = s.trusted || 0
    status.openConns = s.openConns || 0
    status.bans = s.bans || []
  } catch (e: any) {
    ElMessage.error('Status failed: ' + (e.message || e))
  } finally {
    statusLoading.value = false
  }
}

async function clearBans() {
  try {
    await ElMessageBox.confirm('Lift every ban and forget every strike? Trust is kept.', 'Confirm', { type: 'warning' })
  } catch {
    return
  }
  try {
    await http.delete('../api/firewall/bans')
    ElMessage.success('Bans lifted')
    await loadStatus()
  } catch (e: any) {
    ElMessage.error('Failed: ' + (e.message || e))
  }
}
const snap = reactive<Snap>({ enabled: true, controlPort: false, webPort: false, default: 'allow', rules: [], provider: defProvider(), antiAttacker: defAntiAttacker(), domainRefreshSec: 60 })

// What each domain named by a rule resolves to, keyed by name so the rules
// table can show it under the rule that named it.
const domainStatus = ref<DomainStatus[]>([])

async function loadDomainStatus() {
  try {
    domainStatus.value = (await http.get<DomainStatus[]>('../api/firewall/domains')) || []
  } catch {
    // A diagnostic, not the page. The rules themselves are already shown.
    domainStatus.value = []
  }
}

// Empty for a rule whose source is an address or a block - there is nothing to
// resolve and nothing to say.
function domainOf(row: Rule): DomainStatus | undefined {
  const t = (row.cidr || '').trim().toLowerCase().replace(/\.$/, '')
  if (!t) return undefined
  return domainStatus.value.find((d) => d.domain === t)
}

const headersText = computed({
  get: () => Object.entries(snap.provider.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
  set: (t: string) => {
    const h: Record<string, string> = {}
    for (const line of t.split('\n')) {
      const i = line.indexOf(':')
      if (i > 0) h[line.slice(0, i).trim()] = line.slice(i + 1).trim()
    }
    snap.provider.headers = h
  },
})

const dialog = reactive<{ open: boolean; index: number; rule: Rule; duration: string; days: number }>({
  open: false, index: -1, rule: { action: 'deny', cidr: '', port: 'all', note: '' }, duration: '14', days: 14,
})

const page = ref(1)
const pageSize = ref(10)

const pagedRules = computed(() => {
  // Deleting the last row of the last page would otherwise strand us on an
  // empty page.
  const pages = Math.max(1, Math.ceil(snap.rules.length / pageSize.value))
  if (page.value > pages) page.value = pages
  const start = (page.value - 1) * pageSize.value
  return snap.rules.slice(start, start + pageSize.value)
})

// Row position on the current page -> position in the full, ordered rule list.
const rowIndex = (i: number) => (page.value - 1) * pageSize.value + i

function expiryText(exp?: number) {
  if (!exp) return 'permanent'
  const d = Math.round((exp - Date.now() / 1000) / 86400)
  return d <= 0 ? 'expired' : `${d}d`
}

async function load() {
  loading.value = true
  try {
    const s = await http.get<Snap>('../api/firewall')
    snap.enabled = s.enabled
    snap.controlPort = !!s.controlPort
    snap.webPort = !!s.webPort
    snap.default = s.default || 'allow'
    snap.rules = s.rules || []
    snap.provider = { ...defProvider(), ...(s.provider || {}) }
    if (!snap.provider.mode) snap.provider.mode = 'off'
    if (!snap.provider.headers) snap.provider.headers = {}
    snap.domainRefreshSec = s.domainRefreshSec || 60
    const aaDef = defAntiAttacker()
    const aa = s.antiAttacker || ({} as AntiAttacker)
    snap.antiAttacker = {
      ...aaDef, ...aa,
      tcp: { ...aaDef.tcp, ...(aa.tcp || {}) },
      http: { ...aaDef.http, ...(aa.http || {}) },
      udp: { ...aaDef.udp, ...(aa.udp || {}) },
      control: { ...aaDef.control, ...(aa.control || {}) },
      web: { ...aaDef.web, ...(aa.web || {}) },
      ssh: { ...aaDef.ssh, ...(aa.ssh || {}) },
      attack: { ...aaDef.attack, ...(aa.attack || {}) },
      trust: { ...aaDef.trust, ...(aa.trust || {}) },
      strikes: { ...aaDef.strikes, ...(aa.strikes || {}) },
    }
  } catch (e: any) {
    ElMessage.error('Load failed: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

// persist pushes the whole config and reports whether frps took it. Returns
// false on rejection (a bad port spec, say) so callers can undo rather than
// leave the table showing a rule that is not actually in force.
async function persist(okMsg: string) {
  saving.value = true
  try {
    await http.put('../api/firewall', { enabled: snap.enabled, controlPort: snap.controlPort, webPort: snap.webPort, default: snap.default, rules: snap.rules, provider: snap.provider, antiAttacker: snap.antiAttacker, domainRefreshSec: snap.domainRefreshSec })
    ElMessage.success(okMsg)
    return true
  } catch (e: any) {
    ElMessage.error('Save failed: ' + (e.message || e))
    return false
  } finally {
    saving.value = false
  }
}

const save = () => persist('Saved')

// Rule edits take effect on the spot. A rule list that needed a separate Save
// would be a trap in the other direction too: deleting a rule and walking away
// while it is still blocking traffic.
async function applyRules(okMsg: string, undo: Rule[]) {
  if (!(await persist(okMsg))) {
    snap.rules = undo
    return
  }
  // A rule change can add or drop a domain, so what they cover moves with it.
  await loadDomainStatus()
}

function openAdd() {
  dialog.index = -1
  dialog.rule = { action: 'deny', cidr: '', port: 'all', trusted: false, note: '' }
  dialog.duration = '14'; dialog.days = 14
  dialog.open = true
}
function openEdit(i: number) {
  dialog.index = i
  dialog.rule = { ...snap.rules[i], port: snap.rules[i].port || 'all', trusted: !!snap.rules[i].trusted }
  const exp = snap.rules[i].expiresAt
  dialog.duration = !exp ? 'perm' : 'custom'
  dialog.days = exp ? Math.max(1, Math.round((exp - Date.now() / 1000) / 86400)) : 14
  dialog.open = true
}
async function applyDialog() {
  const r = { ...dialog.rule }
  // Blank means every port; say so, rather than leaving the rule looking unset.
  r.port = r.port.trim() || 'all'
  // Trusted means nothing on a deny rule. Cleared rather than carried, so a
  // rule switched from allow to deny does not keep a flag that would come back
  // if it were switched again.
  if (r.action !== 'allow') r.trusted = false
  if (dialog.duration === 'perm') r.expiresAt = 0
  else {
    const days = dialog.duration === '14' ? 14 : dialog.days || 1
    r.expiresAt = Math.floor(Date.now() / 1000) + days * 86400
  }
  const undo = snap.rules.slice()
  if (dialog.index === -1) snap.rules.push(r)
  else snap.rules[dialog.index] = r
  dialog.open = false
  await applyRules(dialog.index === -1 ? 'Rule added and applied' : 'Rule updated and applied', undo)
}
async function removeRule(i: number) {
  const r = snap.rules[i]
  const what = `${r.action} ${r.cidr || 'any IP'} on port ${r.port || 'all'}`
  try {
    await ElMessageBox.confirm(
      `Delete this rule? It stops applying straight away.\n\n${what}`,
      'Delete rule',
      { type: 'warning', confirmButtonText: 'Delete', confirmButtonClass: 'el-button--danger', cancelButtonText: 'Cancel' },
    )
  } catch {
    return // dismissed
  }
  const undo = snap.rules.slice()
  snap.rules.splice(i, 1)
  await applyRules('Rule removed', undo)
}
async function moveUp(i: number) {
  if (i === 0) return
  const undo = snap.rules.slice()
  const r = snap.rules.splice(i, 1)[0]
  snap.rules.splice(i - 1, 0, r)
  await applyRules('Order updated', undo)
}

onMounted(async () => {
  await load()
  if (snap.antiAttacker.enabled) {
    await loadStatus()
  }
  await loadDomainStatus()
})
</script>

<style scoped>
.page-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
.enable-box { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.section { margin-bottom: 16px; }
.card-title { font-weight: 600; margin-bottom: 12px; }
.bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.grow { flex: 1; }
.field { display: flex; flex-direction: column; gap: 6px; }
.pager { margin-top: 12px; display: flex; justify-content: flex-end; }
.field label, .field-grid label, .fg-inline label { font-size: 12px; color: var(--text-muted, #909399); }
.hint { font-size: 12px; color: var(--text-muted, #909399); margin: 0; }
.w120 { width: 120px; } .w160 { width: 160px; } .w220 { width: 220px; } .w90 { width: 90px; }
.field-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.fg-wide { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 6px; }
.field-grid > div:not(.fg-wide):not(.fg-inline) { display: flex; flex-direction: column; gap: 6px; }
.fg-inline { display: flex; align-items: center; gap: 8px; }
/* Inline label for the number fields on the AntiAttacker rows, which sit in a
   .bar rather than a .field and so are not covered by the label rule above. */
.lbl { font-size: 12px; color: var(--text-muted, #909399); white-space: nowrap; }
</style>
