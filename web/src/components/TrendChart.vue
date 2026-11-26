<template>
  <div class="trend-plot">
    <canvas ref="canvas" role="img" :aria-label="title"></canvas>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { Chart, LinearScale, LineController, LineElement, PointElement, Tooltip, Legend } from 'chart.js';

Chart.register(LinearScale, LineController, LineElement, PointElement, Tooltip, Legend);
const props = defineProps({
  title: String,
  rows: { type: Array, required: true },
  series: { type: Array, required: true },
  formatValue: { type: Function, required: true },
  formatTime: { type: Function, required: true },
  ceiling: Number,
  windowMs: Number,
  events: { type: Array, default: () => [] },
  eventLabel: Function,
});
const canvas = ref(null);
let chart;
let observer;

function render() {
  if (!chart) return;
  const style = getComputedStyle(canvas.value);
  const color = name => style.getPropertyValue('--panel-' + name).trim();
  chart.data.datasets = props.series.map(({ key, label }, index) => {
    const validCount = props.rows.reduce((n, row) => n + (row[key] != null ? 1 : 0), 0);
    return {
      label,
      data: props.rows.map(row => ({ x: row.time, y: row[key] ?? null })),
      borderColor: color(index ? 'success' : 'accent'),
      backgroundColor: color(index ? 'success' : 'accent'),
      borderDash: index ? [5, 3] : [],
      borderWidth: 2,
      pointRadius: props.windowMs ? 1 : validCount > 60 ? 0 : 3,
      pointHoverRadius: 5,
    };
  });
  const end = props.rows.at(-1)?.time;
  const scales = chart.options.scales;
  scales.x.min = props.windowMs && end ? end - props.windowMs : props.rows[0]?.time;
  scales.x.max = end;
  scales.y.max = props.ceiling;
  scales.x.ticks.color = scales.y.ticks.color = color('muted');
  scales.y.grid.color = color('line');
  chart.options.plugins.legend.labels.color = color('text');
  chart.update('none');
}

onMounted(() => {
  chart = new Chart(canvas.value, {
    type: 'line',
    data: { datasets: [] },
    plugins: [{
      id: 'coreEvents',
      afterDatasetsDraw(chart) {
        const {ctx, chartArea: area, scales} = chart;
        ctx.save();
        ctx.strokeStyle = getComputedStyle(canvas.value).getPropertyValue('--panel-warning').trim();
        ctx.setLineDash([3, 3]);
        let lastLabelEnd = -Infinity;
        for (const event of props.events) {
          const x = scales.x.getPixelForValue(event.time);
          if (x < area.left || x > area.right) continue;
          ctx.beginPath(); ctx.moveTo(x, area.top); ctx.lineTo(x, area.bottom); ctx.stroke();
          const label = props.eventLabel?.(event);
          if (label) {
            const width = ctx.measureText(label).width;
            const left = Math.min(x + 3, area.right - width);
            if (left >= lastLabelEnd) {
              ctx.fillStyle = ctx.strokeStyle;
              ctx.fillText(label, left, area.top + 12);
              lastLabelEnd = left + width + 4;
            }
          }
        }
        ctx.restore();
      },
    }],
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, parsing: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 14, boxHeight: 2 } },
        tooltip: { callbacks: {
          title: items => props.formatTime(items[0].parsed.x),
          label: item => item.dataset.label + ' · ' + props.formatValue(item.parsed.y),
        } },
      },
      scales: {
        x: { type: 'linear', grid: { display: false }, ticks: { maxTicksLimit: 4, maxRotation: 0, callback: v => props.formatTime(v) } },
        y: { type: 'linear', beginAtZero: true, suggestedMax: 1, ticks: { precision: 0, maxTicksLimit: 4, callback: v => props.formatValue(v) } },
      },
    },
  });
  observer = new MutationObserver(render);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-panel-theme'] });
  render();
});
watch(() => [props.rows, props.series, props.events], render);
onBeforeUnmount(() => { observer?.disconnect(); chart?.destroy(); });
</script>

<style scoped>
.trend-plot { position: relative; contain: inline-size; min-width: 0; height: 12rem; }
.trend-plot canvas { max-inline-size: 100%; }
</style>
