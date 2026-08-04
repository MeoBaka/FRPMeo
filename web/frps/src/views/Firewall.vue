<template>
  <div class="firewall-page" v-loading="loading">
    <div class="page-head">
      <div>
        <h1 class="page-title">Anti-Bot</h1>
        <p class="page-subtitle">
          Measures how a source behaves and turns away the ones that are not
          clients: per-source rate limits, strikes for peers that cannot speak
          the protocol, and trust for those that already held a real connection.
          Everything here runs after the connection is accepted, so it is not a
          defense against volumetric attacks - those never reach frps at all.
        </p>
      </div>
    </div>

    <!-- Kernel ban -->
    <el-card class="section" shadow="never">
      <div class="bar" style="justify-content:space-between">
        <div class="card-title" style="margin:0">Drop banned sources in the kernel</div>
        <el-switch v-model="snap.kernelBan.enabled" @change="save" />
      </div>
      <p class="hint">
        Everything else on this page makes refusing cheap. This makes it free:
        a banned source's packets die in the kernel and never become an accepted
        socket, a goroutine and a lookup. On a small VPS that is the difference
        between a flood costing something and costing nothing.
      </p>
      <p class="hint" style="margin-top:8px">
        Linux only, and it needs ipset, iptables and CAP_NET_ADMIN. Missing any
        of those is not an error - frps says so once at startup and keeps
        enforcing bans by itself. Who is banned never changes either way; this
        only moves where the packet dies, so the switch is safe to flip while
        running. Turning it off takes frps back out of the host firewall.
      </p>
      <div class="bar" style="margin-top:12px" v-if="snap.kernelBan.enabled">
        <label class="lbl">Backend</label>
        <el-select v-model="snap.kernelBan.backend" class="w220" @change="save">
          <el-option label="Auto - use what the host offers" value="auto" />
          <el-option label="ipset (require it)" value="ipset" />
        </el-select>
        <span class="hint">
          Requiring it only changes how loudly frps complains when it is not
          there; it never stops frps from starting.
        </span>
      </div>
    </el-card>

    <!-- AntiAttacker -->
    <el-card class="section" shadow="never">
      <div class="bar" style="justify-content:space-between">
        <div class="card-title" style="margin:0">AntiAttacker (rate limiting)</div>
        <el-switch v-model="snap.antiAttacker.enabled" @change="save" />
      </div>
      <p class="hint">
        How often a source may connect. One over the limit is refused for the
        rest of the window, and only banned once it goes over in several
        separate windows - so one burst throttles, a sustained one blocks. Bans
        expire on their own and are never extended by retries. Off by default: a
        limit set too low turns real users away.
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
        <p class="hint" v-if="snap.antiAttacker.strikes.enabled">
          Strikes short of a ban are not free either: a source with something in
          the ledger gets half the per-source allowance and reaches a ban in half
          the violations, on every rate profile. That middle ground used to mean
          nothing - a peer could fail twice out of three and still be measured
          like one with a clean record. Trust outranks it, so a source that has
          proved itself is not measured at all whatever it did before.
        </p>

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
          <label class="lbl">Handshake byte cap</label>
          <el-input v-model.number="snap.antiAttacker.attack.initialBufferLimitBytes" type="number" class="w120" placeholder="0 = off" />
          <el-button @click="save" :loading="saving">Save</el-button>
        </div>
        <p class="hint" v-if="snap.antiAttacker.attack.enabled">
          The byte cap is how much a peer may send before it has identified
          itself. The timeout above catches the peer that says nothing; this
          catches the opposite one, which says far too much - and the connection
          counters see neither, because one connection is one connection however
          many megabytes it carries. Unlike the timeout it stays armed whether or
          not an attack is under way: 64 KiB is two orders of magnitude above a
          large TLS ClientHello, so it never argues with a real client.
        </p>

        <p class="hint" style="margin-top:12px" v-if="snap.antiAttacker.attack.enabled">
          Bans are only handed out while this state is on. A quiet server
          throttles a source that overflows its window but does not lock it out -
          the violations still accumulate, so a source that carries on into an
          attack is banned on the first overflow. With this switch off there is
          no state to consult and bans escalate as they otherwise would.
        </p>

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

  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { http } from '../api/http'

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
  attack: { enabled: boolean; connectionsPerSec: number; cooldownSec: number; initialTimeoutMs: number; initialBufferLimitBytes: number }
  trust: { enabled: boolean; afterMs: number; minBytes: number; forSeconds: number; maxTracked: number }
  strikes: {
    enabled: boolean; protocolFailures: number; emptyConnections: number
    emptyBytes: number; banSeconds: number; forgetMs: number; maxTracked: number
  }
}
interface BanEntry { source: string; tier: string; reason: string; secondsLeft: number }
interface FwStatus {
  underAttack: boolean; inGrace: boolean
  tracked: Record<string, number>; trusted: number; openConns: number; bans: BanEntry[]
}
interface KernelBan { enabled: boolean; backend: string }

interface Snap {
  antiAttacker: AntiAttacker
  kernelBan: KernelBan
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
    attack: { enabled: false, connectionsPerSec: 40, cooldownSec: 60, initialTimeoutMs: 2000, initialBufferLimitBytes: 65536 },
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
const snap = reactive<Snap>({ antiAttacker: defAntiAttacker(), kernelBan: { enabled: false, backend: 'auto' } })

async function load() {
  loading.value = true
  try {
    const s = await http.get<Snap>('../api/firewall')
    snap.kernelBan = { enabled: !!s.kernelBan?.enabled, backend: s.kernelBan?.backend || 'auto' }
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

// persist pushes the whole config and reports whether frps took it.
async function persist(okMsg: string) {
  saving.value = true
  try {
    await http.put('../api/firewall', { antiAttacker: snap.antiAttacker, kernelBan: snap.kernelBan })
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

onMounted(async () => {
  await load()
  if (snap.antiAttacker.enabled) {
    await loadStatus()
  }
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
