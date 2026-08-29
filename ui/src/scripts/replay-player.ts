import rrwebPlayer from 'rrweb-player';
import 'rrweb-player/dist/style.css';

type ReplayEvent = {
  type: number;
  timestamp: number;
  data?: unknown;
};

type ReplayPlayerInstance = {
  $destroy: () => void;
  pause?: () => void;
};

type ReplayPlayerAPI = {
  mount: (target: HTMLElement, events: ReplayEvent[]) => void;
  destroy: () => void;
};

let player: ReplayPlayerInstance | null = null;

const destroy = () => {
  if (!player) return;
  player.pause?.();
  player.$destroy();
  player = null;
};

const mount = (target: HTMLElement, events: ReplayEvent[]) => {
  destroy();
  target.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) return;

  const width = Math.max(240, Math.min(1024, target.clientWidth || 800));
  const height = Math.max(220, Math.min(576, Math.round(width * 9 / 16)));
  player = new rrwebPlayer({
    target,
    props: {
      events,
      width,
      height,
      maxScale: 1,
      autoPlay: false,
      showController: true,
      skipInactive: true,
    },
  });
  target.dataset.mounted = 'true';
};

declare global {
  interface Window {
    BarktraceReplayPlayer?: ReplayPlayerAPI;
  }
}

window.BarktraceReplayPlayer = { mount, destroy };
window.dispatchEvent(new Event('barktrace:replay-player-ready'));
