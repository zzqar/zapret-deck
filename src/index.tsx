import {
  ButtonItem,
  DropdownItem,
  Field,
  PanelSection,
  PanelSectionRow,
  ToggleField,
  staticClasses,
} from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useCallback, useEffect, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";

type Strategy = { id: string; name: string; description: string };
type HostList = { id: string; enabled: boolean; count: number };
type State = {
  running: boolean;
  enabled: boolean;
  dns: boolean;
  dns_running: boolean;
  dns_error: string;
  auto_count: number;
  autostart: boolean;
  strategy: string;
  strategies: Strategy[];
  lists: HostList[];
  nfqws_installed: boolean;
  firewall: string | null;
  error: string;
  data_dir: string;
};
type Result = { ok: boolean; error?: string; version?: string };
type CheckResult = { ok: boolean; url: string; code?: number; time?: number; ip?: string; error?: string };

const getState = callable<[], State>("get_state");
const setEnabled = callable<[enabled: boolean], Result>("set_enabled");
const setDns = callable<[enabled: boolean], Result>("set_dns");
const clearAuto = callable<[], Result>("clear_autohostlist");
const setStrategy = callable<[id: string], Result>("set_strategy");
const setList = callable<[id: string, enabled: boolean], Result>("set_list");
const setAutostart = callable<[enabled: boolean], Result>("set_autostart");
const restart = callable<[], Result>("restart");
const installNfqws = callable<[], Result>("install_nfqws");
const checkUrl = callable<[url: string], CheckResult>("check_url");
const getLog = callable<[], string>("get_log");

const CHECK_URLS = [
  "https://store.steampowered.com/",
  "https://steamcommunity.com/",
  "https://help.steampowered.com/",
  "https://store.fastly.steamstatic.com/",
  "https://apis.roblox.com/",
  "https://web.telegram.org/",
];

const notifyError = (r: Result) => {
  if (!r.ok) toaster.toast({ title: "Zapret Deck", body: r.error ?? "Ошибка" });
};

const preStyle = {
  whiteSpace: "pre-wrap" as const,
  wordBreak: "break-all" as const,
  fontSize: "10px",
  maxHeight: "160px",
  overflowY: "auto" as const,
  margin: 0,
};

function Content() {
  const [state, setState] = useState<State | null>(null);
  const [busy, setBusy] = useState(false);
  const [checks, setChecks] = useState<CheckResult[]>([]);
  const [log, setLog] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setState(await getState());
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  const act = async (fn: () => Promise<Result>) => {
    setBusy(true);
    try {
      notifyError(await fn());
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const runChecks = async () => {
    setBusy(true);
    setChecks([]);
    try {
      setChecks(await Promise.all(CHECK_URLS.map((u) => checkUrl(u))));
    } finally {
      setBusy(false);
    }
  };

  if (!state) {
    return (
      <PanelSection>
        <PanelSectionRow>Загрузка…</PanelSectionRow>
      </PanelSection>
    );
  }

  const status = state.running
    ? `Работает · ${state.firewall ?? "?"}`
    : state.enabled
      ? "Запускается…"
      : "Выключено";

  return (
    <>
      <PanelSection title="Обход DPI">
        <PanelSectionRow>
          <ToggleField
            label="Включить"
            description={status}
            checked={state.enabled}
            disabled={busy || !state.nfqws_installed}
            onChange={(v) => act(() => setEnabled(v))}
          />
        </PanelSectionRow>

        <PanelSectionRow>
          <ToggleField
            label="Защищённый DNS"
            description={
              state.dns_error
                ? state.dns_error
                : state.dns_running
                  ? "DNS-over-TLS → 1.1.1.1 / 8.8.8.8"
                  : "Провайдер подменяет DNS Steam на 127.0.0.1"
            }
            checked={state.dns}
            disabled={busy}
            onChange={(v) => act(() => setDns(v))}
          />
        </PanelSectionRow>

        {!state.nfqws_installed && (
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy}
              onClick={() =>
                act(async () => {
                  const r = await installNfqws();
                  if (r.ok) toaster.toast({ title: "Zapret Deck", body: `nfqws ${r.version} установлен` });
                  return r;
                })
              }
            >
              {busy ? "Скачиваю…" : "Скачать nfqws"}
            </ButtonItem>
          </PanelSectionRow>
        )}

        <PanelSectionRow>
          <DropdownItem
            label="Стратегия"
            description={state.strategies.find((s) => s.id === state.strategy)?.description}
            disabled={busy}
            rgOptions={state.strategies.map((s) => ({ data: s.id, label: s.name }))}
            selectedOption={state.strategy}
            onChange={(opt) => act(() => setStrategy(opt.data as string))}
          />
        </PanelSectionRow>

        <PanelSectionRow>
          <ToggleField
            label="Автозапуск"
            description="Включать при загрузке Deck, если было включено"
            checked={state.autostart}
            onChange={(v) => act(() => setAutostart(v))}
          />
        </PanelSectionRow>

        {state.error && (
          <PanelSectionRow>
            <Field label="Ошибка" bottomSeparator="none" />
            <pre style={{ ...preStyle, color: "#ff8080" }}>{state.error}</pre>
          </PanelSectionRow>
        )}
      </PanelSection>

      <PanelSection title="Хостлисты">
        {state.lists.map((l) => (
          <PanelSectionRow key={l.id}>
            <ToggleField
              label={l.id.replace(/\.txt$/, "")}
              description={`${l.count} доменов`}
              checked={l.enabled}
              disabled={busy}
              onChange={(v) => act(() => setList(l.id, v))}
            />
          </PanelSectionRow>
        ))}
        <PanelSectionRow>
          <div style={{ fontSize: "11px", opacity: 0.7 }}>
            Автосписок (заблокированное, найденное само): {state.auto_count} доменов. exclude.txt
            никогда не трогается.
            <br />
            Свои стратегии и списки: {state.data_dir}
          </div>
        </PanelSectionRow>
        {state.auto_count > 0 && (
          <PanelSectionRow>
            <ButtonItem layout="below" disabled={busy} onClick={() => act(clearAuto)}>
              Очистить автосписок
            </ButtonItem>
          </PanelSectionRow>
        )}
      </PanelSection>

      <PanelSection title="Диагностика">
        <PanelSectionRow>
          <ButtonItem layout="below" disabled={busy} onClick={runChecks}>
            Проверить Steam
          </ButtonItem>
        </PanelSectionRow>
        {checks.map((c) => (
          <PanelSectionRow key={c.url}>
            <Field
              label={new URL(c.url).hostname}
              description={c.ok ? `HTTP ${c.code} · ${c.time?.toFixed(2)} c · ${c.ip}` : c.error}
            >
              {c.ok ? "✅" : "❌"}
            </Field>
          </PanelSectionRow>
        ))}
        <PanelSectionRow>
          <ButtonItem layout="below" disabled={busy || !state.enabled} onClick={() => act(restart)}>
            Перезапустить nfqws
          </ButtonItem>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            onClick={async () => setLog(log === null ? await getLog() : null)}
          >
            {log === null ? "Показать лог" : "Скрыть лог"}
          </ButtonItem>
        </PanelSectionRow>
        {log !== null && (
          <PanelSectionRow>
            <pre style={preStyle}>{log || "(пусто)"}</pre>
          </PanelSectionRow>
        )}
        {state.nfqws_installed && (
          <PanelSectionRow>
            <ButtonItem layout="below" disabled={busy || state.enabled} onClick={() => act(installNfqws)}>
              Обновить nfqws
            </ButtonItem>
          </PanelSectionRow>
        )}
      </PanelSection>
    </>
  );
}

export default definePlugin(() => ({
  name: "Zapret Deck",
  titleView: <div className={staticClasses.Title}>Zapret Deck</div>,
  content: <Content />,
  icon: <FaShieldAlt />,
}));
