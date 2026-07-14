<template>
  <div class="firewall-page">
    <div class="page-head">
      <div>
        <h1 class="page-title">Firewall</h1>
        <p class="page-subtitle">
          Access rules enforced natively by this frps. Incoming user connections
          are allowed or rejected before reaching the tunneled service.
        </p>
      </div>
    </div>

    <el-card class="section" shadow="never">
      <div class="bar">
        <div class="field">
          <label>Default policy</label>
          <el-select v-model="ruleset.default" class="policy-select">
            <el-option label="allow" value="allow" />
            <el-option label="deny" value="deny" />
          </el-select>
        </div>
        <div class="field grow" />
        <el-button @click="openAdd">Add rule</el-button>
        <el-button type="primary" :loading="saving" @click="save">Save</el-button>
      </div>
      <p class="hint">
        Rules are evaluated top to bottom; the first match wins, otherwise the
        default policy applies. Blank CIDR / proxy / user matches anything.
      </p>
    </el-card>

    <el-card class="section" shadow="never" v-loading="loading">
      <el-table :data="ruleset.rules" empty-text="No rules - default policy applies to all">
        <el-table-column label="Action" width="100">
          <template #default="{ row }">
            <el-tag :type="row.action === 'allow' ? 'success' : 'danger'" disable-transitions>
              {{ row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="CIDR / IP" min-width="140">
          <template #default="{ row }">{{ row.cidr || 'any' }}</template>
        </el-table-column>
        <el-table-column label="Proxy" min-width="120">
          <template #default="{ row }">{{ row.proxy || 'any' }}</template>
        </el-table-column>
        <el-table-column label="User" min-width="100">
          <template #default="{ row }">{{ row.user || 'any' }}</template>
        </el-table-column>
        <el-table-column label="Note" prop="note" min-width="140" />
        <el-table-column label="" width="170" align="right">
          <template #default="{ $index }">
            <el-button size="small" @click="moveUp($index)" :disabled="$index === 0">Up</el-button>
            <el-button size="small" @click="openEdit($index)">Edit</el-button>
            <el-button size="small" type="danger" @click="remove($index)">Del</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialog.open" :title="dialog.index === -1 ? 'Add rule' : 'Edit rule'" width="480px">
      <el-form label-width="90px">
        <el-form-item label="Action">
          <el-select v-model="dialog.rule.action">
            <el-option label="allow" value="allow" />
            <el-option label="deny" value="deny" />
          </el-select>
        </el-form-item>
        <el-form-item label="CIDR / IP">
          <el-input v-model="dialog.rule.cidr" placeholder="1.2.3.0/24 or 1.2.3.4 (blank = any)" />
        </el-form-item>
        <el-form-item label="Proxy">
          <el-input v-model="dialog.rule.proxy" placeholder="rdp-* (blank = any)" />
        </el-form-item>
        <el-form-item label="User">
          <el-input v-model="dialog.rule.user" placeholder="admin (blank = any)" />
        </el-form-item>
        <el-form-item label="Note">
          <el-input v-model="dialog.rule.note" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog.open = false">Cancel</el-button>
        <el-button type="primary" @click="applyDialog">OK</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { http } from '../api/http'

interface Rule {
  id?: string
  action: string
  cidr: string
  proxy: string
  user: string
  note: string
}
interface RuleSet {
  default: string
  rules: Rule[]
}

const loading = ref(false)
const saving = ref(false)
const ruleset = reactive<RuleSet>({ default: 'allow', rules: [] })

const dialog = reactive<{ open: boolean; index: number; rule: Rule }>({
  open: false,
  index: -1,
  rule: { action: 'deny', cidr: '', proxy: '', user: '', note: '' },
})

async function load() {
  loading.value = true
  try {
    const rs = await http.get<RuleSet>('../api/firewall')
    ruleset.default = rs.default || 'allow'
    ruleset.rules = rs.rules || []
  } catch (e: any) {
    ElMessage.error('Load failed: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    await http.put('../api/firewall', { default: ruleset.default, rules: ruleset.rules })
    ElMessage.success('Saved')
    await load()
  } catch (e: any) {
    ElMessage.error('Save failed: ' + (e.message || e))
  } finally {
    saving.value = false
  }
}

function openAdd() {
  dialog.index = -1
  dialog.rule = { action: 'deny', cidr: '', proxy: '', user: '', note: '' }
  dialog.open = true
}
function openEdit(index: number) {
  dialog.index = index
  dialog.rule = { ...ruleset.rules[index] }
  dialog.open = true
}
function applyDialog() {
  if (dialog.index === -1) {
    ruleset.rules.push({ ...dialog.rule })
  } else {
    ruleset.rules[dialog.index] = { ...dialog.rule }
  }
  dialog.open = false
}
function remove(index: number) {
  ruleset.rules.splice(index, 1)
}
function moveUp(index: number) {
  if (index === 0) return
  const r = ruleset.rules.splice(index, 1)[0]
  ruleset.rules.splice(index - 1, 0, r)
}

onMounted(load)
</script>

<style scoped>
.page-head {
  margin-bottom: 20px;
}
.section {
  margin-bottom: 16px;
}
.bar {
  display: flex;
  gap: 16px;
  align-items: flex-end;
  flex-wrap: wrap;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.field label {
  font-size: 12px;
  color: var(--text-muted, #909399);
}
.field.grow {
  flex: 1;
}
.policy-select {
  width: 120px;
}
.hint {
  font-size: 12px;
  color: var(--text-muted, #909399);
  margin: 12px 0 0;
}
</style>
