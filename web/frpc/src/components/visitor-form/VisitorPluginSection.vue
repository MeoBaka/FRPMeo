<template>
  <ConfigSection title="Plugin" :readonly="readonly">
    <div class="field-row two-col">
      <ConfigField label="Plugin" type="select" v-model="form.pluginType"
        :options="PLUGIN_OPTIONS" :readonly="readonly" />
      <div></div>
    </div>

    <template v-if="form.pluginType === 'virtual_net'">
      <ConfigField label="Destination IP" type="text" v-model="destinationIP"
        placeholder="10.10.10.10" :readonly="readonly" />
    </template>
  </ConfigSection>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import type { VisitorFormData } from '../../types'
import ConfigSection from '../ConfigSection.vue'
import ConfigField from '../ConfigField.vue'

// Visitor plugins supported by the core (pkg/config/v1/visitor_plugin.go).
// Only virtual_net today; kept as a list so new visitor plugins are easy to add.
const PLUGIN_OPTIONS = [
  { label: 'None', value: '' },
  { label: 'virtual_net', value: 'virtual_net' },
]

const props = withDefaults(defineProps<{
  modelValue: VisitorFormData
  readonly?: boolean
}>(), { readonly: false })

const emit = defineEmits<{ 'update:modelValue': [value: VisitorFormData] }>()

const form = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const destinationIP = computed({
  get: () => form.value.pluginConfig?.destinationIP ?? '',
  set: (val: string) => {
    if (!form.value.pluginConfig) form.value.pluginConfig = {}
    form.value.pluginConfig.destinationIP = val
  },
})

// Reset plugin config only when switching between two real plugin types, so a
// previous plugin's fields don't leak. Hydration ('' -> a plugin) has a falsy
// oldType and is skipped, preserving loaded config.
watch(() => form.value.pluginType, (newType, oldType) => {
  if (!oldType || !newType || newType === oldType) return
  if (form.value.pluginConfig && Object.keys(form.value.pluginConfig).length > 0) {
    form.value.pluginConfig = {}
  }
})
</script>

<style scoped lang="scss">
@use '@/assets/css/form-layout';
</style>
