import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const ROOT = "/opt/lebleu-listing-bridge";
const PREVIEW_PHOTO_LIMIT = 4;
const PHOTO_SOURCE_CANDIDATE_LIMIT = 8;
const MEDIA_VERSION = "album-4-v1";
const CTA_VERSION = "growth-detail-share-v2";
const CATALOG = `${ROOT}/public/data/full/catalog.json`;
const FAILURES = `${ROOT}/public/data/full/failures.json`;
const STATE_FILE = `${ROOT}/state/telegram-state.json`;
const TOPICS_FILE = `${ROOT}/state/forum-topics.json`;
const CONFIG_FILE = `${ROOT}/publisher.env`;
const QUALITY_CONTENT_FILE = `${ROOT}/state/ru-content-quality.json`;
const CRM_ENV = "/opt/fiodor-crm-v2/.env";
const GROWTH_ENV = "/opt/growth-core/.env";

type Item = {
  sourceUrl: string; code?: string; slug: string; operation?: string;
  propertyType?: string; address?: string; priceAmount?: string;
  priceCurrency?: string; expensesAmount?: string; expensesCurrency?: string;
  details?: Record<string, number>; highlightedFeatures?: string[];
  imageUrls?: string[]; sourceFingerprint?: string; description?: string;
};
type QualityContent = { code?: string; operation?: string; sourceFingerprint?: string; summary_ru?: string; notes_ru?: string[]; details_override?: Record<string, number>; property_type_override?: string | null };
type Entry = {
  code: string; sourceUrl: string; status: "active" | "removed";
  textHash: string; photoHash: string; leadHash?: string; messageIds: number[];
  threadId?: number; ctaMessageId?: number; mode: "album" | "media" | "text"; caption: string; updatedAt: string;
  botUsername?: string;
};
type State = { channel: string; entries: Record<string, Entry> };
function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const i = line.indexOf("=");
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^['"]|['"]$/g, "");
  }
  return out;
}
function esc(s: unknown): string {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function hash(value: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function fmt(n?: string): string | undefined {
  if (!n) return;
  const x = Number(n);
  if (!Number.isFinite(x)) return n;
  return new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 0 }).format(x);
}
function codeOf(item: Item): string {
  return (item.code || item.slug || hash(item.sourceUrl).slice(0, 12)).trim();
}
function effectiveType(item: Item, q?: QualityContent): string | undefined {
  if (q?.property_type_override) return q.property_type_override;
  if (item.propertyType) return item.propertyType;
  const hay = `${item.slug || ""} ${item.description || ""} ${item.sourceUrl || ""}`.toLowerCase();
  if (hay.includes("finca")) return "Finca";
  if (hay.includes("edificio en block") || hay.includes("edificio comercial")) return "Edificio Comercial";
  if (hay.includes("galpón") || hay.includes("galpon")) return "Galpón";
  if (/\bcampo\b/.test(hay)) return "Campo";
  return undefined;
}
function forumTopicKey(item: Item, q?: QualityContent): string | null {
  if (codeOf(item) === "LAP9861952") return "temporary";
  const type = effectiveType(item, q);
  const op = item.operation || "";
  if (type === "Departamento" || type === "PH") return op === "Alquiler" ? "rent_apartments" : "sale_apartments";
  if (type === "Casa") return op === "Alquiler" ? "rent_houses" : "sale_houses";
  if (type === "Cochera") return "parking";
  if (["Terreno", "Terreno o Lote", "Finca", "Campo"].includes(type || "")) return "land";
  if (["Oficina", "Local Comercial", "Edificio Comercial", "Galpón", "Depósito"].includes(type || "")) return "commercial";
  return null;
}

function operationLabel(item: Item): string {
  // LAP9861952 is verified in the 2026-09-25 Le Bleu export as both regular and temporary rental.
  if (codeOf(item) === "LAP9861952" && item.operation === "Alquiler") return "Аренда / временная аренда";
  return OP[item.operation || ""] || "Объект";
}
function suspiciousPublicPrice(item: Item, q?: QualityContent): boolean {
  const price = Number(item.priceAmount || "0");
  return item.operation === "Venta" && item.priceCurrency === "USD" && Number.isFinite(price) && price > 0 && price < 5000 && effectiveType(item, q) !== "Cochera";
}
function startPayload(item: Item): string {
  // Must match CRM token generation exactly: SHA-256 of the raw source URL.
  const unique = crypto.createHash("sha256").update(item.sourceUrl).digest("hex").slice(0, 8);
  return (`lb_${codeOf(item)}_${unique}`).replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64);
}

type GrowthConfig = { url: string; key: string; tenant: string };
type LeadInfo = { url: string; marker: string };
type GrowthAttribution = {
  source: string; medium: string; campaign: string; content: string; placement: string;
};

async function trackedLead(
  item: Item,
  bot: string,
  growth?: GrowthConfig,
  attribution: GrowthAttribution = {
    source: "telegram_catalog",
    medium: "owned",
    campaign: "live_catalog",
    content: "listing",
    placement: "forum_card",
  },
): Promise<LeadInfo> {
  const legacyPayload = startPayload(item);
  const fallback = {
    url: `https://t.me/${bot.replace(/^@/, "")}?start=${legacyPayload}`,
    marker: legacyPayload,
  };
  if (!growth?.url || !growth.key) return fallback;
  const listingToken = legacyPayload.replace(/^lb_/, "");
  try {
    const response = await fetch(`${growth.url.replace(/\/$/, "")}/v1/links/ensure`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-growth-key": growth.key,
      },
      body: JSON.stringify({
        tenant: growth.tenant,
        source: attribution.source,
        medium: attribution.medium,
        campaign: attribution.campaign,
        content: attribution.content,
        placement: attribution.placement,
        listing_code: listingToken,
        intent: "listing",
        bot_username: bot.replace(/^@/, ""),
        metadata: { code: codeOf(item), source_url: item.sourceUrl, surface: attribution.placement },
      }),
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error(`growth HTTP ${response.status}`);
    const data = await response.json() as { telegram_url?: string; token?: string };
    if (!data.telegram_url || !data.token) throw new Error("growth link response incomplete");
    return { url: data.telegram_url, marker: `trk_${data.token}` };
  } catch (error) {
    console.warn(`GROWTH_FALLBACK ${codeOf(item)} ${String(error)}`);
    return fallback;
  }
}
function qualityReasons(item: Item, q?: QualityContent): string[] {
  const reasons: string[] = [];
  const d = item.details || {};
  const price = Number(item.priceAmount || "0");
  if (!item.code) reasons.push("missing_code");
  if (!item.operation || !["Venta", "Alquiler", "Alquiler temporario"].includes(item.operation)) reasons.push("bad_operation");
  if (!effectiveType(item, q)) reasons.push("missing_type");
  if (!(item.imageUrls || []).length) reasons.push("no_photo");
  if (!item.address || item.address.length < 4) reasons.push("bad_address");
  if (!Number.isFinite(price) || price <= 0) reasons.push("bad_price");
  if (d.totalAreaM2 !== undefined && (d.totalAreaM2 <= 5 || d.totalAreaM2 > 50000)) reasons.push("suspicious_area");
  if (d.rooms !== undefined && (d.rooms <= 0 || d.rooms > 30)) reasons.push("suspicious_rooms");
  if (d.bedrooms !== undefined && (d.bedrooms < 0 || d.bedrooms > 20)) reasons.push("suspicious_bedrooms");
  if (d.bathrooms !== undefined && (d.bathrooms < 0 || d.bathrooms > 20)) reasons.push("suspicious_bathrooms");
  return reasons;
}
const OP: Record<string, string> = {
  Venta: "Продажа", Alquiler: "Аренда", "Alquiler temporario": "Посуточная аренда",
  "En Pozo": "На стадии строительства",
};
const TYPE: Record<string, string> = {
  Departamento: "Квартира", Casa: "Дом", PH: "PH",
  Terreno: "Участок", "Terreno o Lote": "Участок",
  "Local Comercial": "Коммерческое помещение", Oficina: "Офис",
  Cochera: "Парковочное место", "Depósito": "Склад", Propiedad: "Объект",
  Finca: "Финка / загородное владение", Campo: "Земельный участок / поле",
  "Edificio Comercial": "Коммерческое здание", "Galpón": "Склад / производственное помещение",
};
const FEATURE: Record<string, string> = {
  "Balcón": "Балкон", Terraza: "Терраса", Parrilla: "Зона барбекю",
  Quincho: "Крытая зона отдыха (quincho)", Patio: "Патио", "Jardín": "Сад", Gimnasio: "Спортзал",
  SUM: "Общий зал (SUM)", "Seguridad 24": "Охрана 24/7", Ascensor: "Лифт",
  Baulera: "Кладовая", Amoblado: "Меблировано", "Apto crédito": "Подходит под ипотеку",
  "Apto profesional": "Подходит для профессионального использования",
  "Aire acondicionado": "Кондиционер", "Aire Acondicionado": "Кондиционер",
  "Calefacción": "Отопление", Luminoso: "Светлая", "A estrenar": "Новый объект",
  Laundry: "Прачечная", Solarium: "Терраса-солярий", Piscina: "Бассейн", Pileta: "Бассейн",
};
function plural(n: number, one: string, few: string, many: string): string {
  const n10 = n % 10, n100 = n % 100;
  if (n10 === 1 && n100 !== 11) return one;
  if (n10 >= 2 && n10 <= 4 && !(n100 >= 12 && n100 <= 14)) return few;
  return many;
}
function render(item: Item, bot: string, q?: QualityContent): string {
  const d = { ...(item.details || {}), ...(q?.details_override || {}) };
  const op = operationLabel(item);
  const rawType = effectiveType(item, q);
  const type = TYPE[rawType || ""] || rawType || "Объект";
  const icon = rawType === "Cochera" ? "🚗" : rawType === "Terreno o Lote" || rawType === "Terreno" ? "🌳"
    : rawType === "Finca" || rawType === "Campo" ? "🌾" : rawType === "Galpón" ? "🏭"
    : rawType === "Local Comercial" || rawType === "Edificio Comercial" || rawType === "Oficina" ? "🏢"
    : rawType === "Casa" ? "🏡" : "🏠";
  const specs: string[] = [];
  if (d.totalAreaM2) specs.push(`${d.totalAreaM2} м²`);
  else if (d.coveredAreaM2) specs.push(`${d.coveredAreaM2} м² крытой`);
  if (rawType !== "Cochera") {
    if (d.rooms) specs.push(`${d.rooms} ${plural(d.rooms, "комната", "комнаты", "комнат")}`);
    if (d.bedrooms) specs.push(`${d.bedrooms} ${plural(d.bedrooms, "спальня", "спальни", "спален")}`);
    if (d.bathrooms) specs.push(`${d.bathrooms} ${plural(d.bathrooms, "санузел", "санузла", "санузлов")}`);
  }
  const allowedParkingFeatures = new Set(["Ascensor", "Apto crédito"]);
  const sourceFeatures = rawType === "Cochera"
    ? (item.highlightedFeatures || []).filter(x => allowedParkingFeatures.has(x))
    : (item.highlightedFeatures || []).filter(x => !(item.operation === "Alquiler" && x === "Apto crédito"));
  const features = sourceFeatures.map(x => FEATURE[x]).filter((x): x is string => Boolean(x)).slice(0, 6);
  const badPrice = suspiciousPublicPrice(item, q);
  const price = badPrice ? "По запросу" : item.priceAmount
    ? `${item.priceCurrency === "USD" ? "USD" : esc(item.priceCurrency || "")} ${fmt(item.priceAmount)}`
    : "По запросу";
  const expense = item.expensesAmount
    ? `${item.expensesCurrency === "USD" ? "USD" : esc(item.expensesCurrency || "ARS")} ${fmt(item.expensesAmount)}`
    : undefined;
  const summary = (q?.summary_ru || "").replace(/\s+/g, " ").trim();
  const notes = (q?.notes_ru || []).map(x => String(x).replace(/\s+/g, " ").trim()).filter(Boolean).slice(0, 4);
  const photoCount = Math.min(PREVIEW_PHOTO_LIMIT, (item.imageUrls || []).length);
  const lines = [
    `${icon} <b>${esc(op)} · ${esc(type)}</b>`,
    item.address ? `📍 ${esc(item.address)}` : undefined,
    `💵 <b>${price}</b>`,
    badPrice ? `⚠️ Цена в исходной базе требует уточнения.` : undefined,
    specs.length ? `📐 ${esc(specs.join(" · "))}` : undefined,
    expense ? `💳 Коммунальные расходы (expensas): ${expense}` : undefined,
    features.length ? `✨ ${esc(features.join(" · "))}` : undefined,
    summary ? "" : undefined,
    summary ? esc(summary.slice(0, 560)) : undefined,
    notes.length ? "" : undefined,
    notes.length ? `<b>Важно:</b> ${esc(notes.join(" · ").slice(0, 360))}` : undefined,
    "",
    photoCount > 1
      ? `📸 ${photoCount} фото в альбоме. Полная галерея, актуальность и просмотр — по кнопке ниже.`
      : "👇 Полная галерея, актуальность и просмотр — по кнопке ниже.",
  ].filter((x): x is string => x !== undefined);
  return lines.join("\n").slice(0, 1000);
}
async function api(token: string, method: string, payload: Record<string, unknown>): Promise<any> {
  let lastNetworkError: unknown = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let r: Response;
    try {
      r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(payload), signal: AbortSignal.timeout(10000),
      });
    } catch (error) {
      lastNetworkError = error;
      if (attempt < 1) {
        await new Promise(resolve => setTimeout(resolve, 700));
        continue;
      }
      throw error;
    }
    const body: any = await r.json().catch(() => ({}));
    if (body.ok) return body.result;
    const retry = Number(body?.parameters?.retry_after || 0);
    if ((r.status === 429 || retry) && attempt < 1) {
      await new Promise(resolve => setTimeout(resolve, Math.max(1, retry) * 1000 + 750));
      continue;
    }
    throw new Error(`${method}: ${body?.description || `HTTP ${r.status}`}`);
  }
  throw lastNetworkError instanceof Error ? lastNetworkError : new Error(`${method}: retries exhausted`);
}

type DownloadedPhoto = { url: string; bytes: Uint8Array; mime: string; filename: string };
async function downloadPreviewPhotos(urls: string[]): Promise<DownloadedPhoto[]> {
  const candidates = urls.slice(0, PHOTO_SOURCE_CANDIDATE_LIMIT);
  const results = await Promise.all(candidates.map(async (url, i): Promise<DownloadedPhoto | null> => {
    try {
      const r = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0", "Accept": "image/*" },
        signal: AbortSignal.timeout(7000),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const mime = (r.headers.get("content-type") || "image/jpeg").split(";")[0].trim();
      if (!mime.startsWith("image/")) throw new Error(`not image: ${mime}`);
      const bytes = new Uint8Array(await r.arrayBuffer());
      if (bytes.byteLength < 8_000) throw new Error(`too small: ${bytes.byteLength}`);
      if (bytes.byteLength > 9_500_000) throw new Error(`too large: ${bytes.byteLength}`);
      const ext = mime.includes("png") ? "png" : mime.includes("webp") ? "webp" : "jpg";
      return { url, bytes, mime, filename: `photo-${i + 1}.${ext}` };
    } catch (error) {
      console.warn(`PHOTO_SKIP ${url} ${String(error)}`);
      return null;
    }
  }));
  return results.filter((x): x is DownloadedPhoto => Boolean(x)).slice(0, PREVIEW_PHOTO_LIMIT);
}
async function multipartApi(
  token: string,
  method: string,
  fields: Record<string, unknown>,
  files: Array<{ field: string; photo: DownloadedPhoto }>,
): Promise<any> {
  let lastNetworkError: unknown = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const form = new FormData();
    for (const [key, value] of Object.entries(fields)) {
      if (value === undefined || value === null) continue;
      form.set(key, typeof value === "string" ? value : JSON.stringify(value));
    }
    for (const { field, photo } of files) {
      form.set(field, new Blob([photo.bytes], { type: photo.mime }), photo.filename);
    }
    let r: Response;
    try {
      r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
        method: "POST", body: form, signal: AbortSignal.timeout(12000),
      });
    } catch (error) {
      lastNetworkError = error;
      if (attempt < 1) {
        await new Promise(resolve => setTimeout(resolve, 700));
        continue;
      }
      throw error;
    }
    const body: any = await r.json().catch(() => ({}));
    if (body.ok) return body.result;
    const retry = Number(body?.parameters?.retry_after || 0);
    if ((r.status === 429 || retry) && attempt < 1) {
      await new Promise(resolve => setTimeout(resolve, Math.max(1, retry) * 1000 + 750));
      continue;
    }
    throw new Error(`${method}: ${body?.description || `HTTP ${r.status}`}`);
  }
  throw lastNetworkError instanceof Error ? lastNetworkError : new Error(`${method}: retries exhausted`);
}
async function postItem(token: string, channel: string, item: Item, caption: string, bot: string, threadId: number, leadUrl?: string, shareLeadUrl?: string): Promise<Entry> {
  const candidateUrls = (item.imageUrls || []).slice(0, PHOTO_SOURCE_CANDIDATE_LIMIT);
  const photos = await downloadPreviewPhotos(candidateUrls);
  const lead = leadUrl || `https://t.me/${bot.replace(/^@/, "")}?start=${startPayload(item)}`;
  const shareTarget = shareLeadUrl || lead;
  const share = `https://t.me/share/url?url=${encodeURIComponent(shareTarget)}`;
  const reply_markup = { inline_keyboard: [[
    { text: "Узнать подробнее", url: lead },
    { text: "Поделиться", url: share },
  ]] };
  let messageIds: number[] = [], ctaMessageId: number | undefined, mode: "album" | "media" | "text" = "text";
  if (photos.length >= 2) {
    const media = photos.map((photo, i) => ({
      type: "photo",
      media: `attach://p${i}`,
      ...(i === 0 ? { caption, parse_mode: "HTML" } : {}),
    }));
    let albumIds: number[] = [];
    try {
      const result = await multipartApi(token, "sendMediaGroup", {
        chat_id: channel, message_thread_id: threadId, media, disable_notification: true,
      }, photos.map((photo, i) => ({ field: `p${i}`, photo })));
      albumIds = (result || []).map((x: any) => Number(x.message_id)).filter(Boolean);
      if (!albumIds.length) throw new Error("sendMediaGroup returned no message IDs");
      let cta: any;
      try {
        cta = await api(token, "sendMessage", {
          chat_id: channel, message_thread_id: threadId,
          text: "Подробности, актуальность и запись на просмотр",
          reply_parameters: { message_id: albumIds[0], allow_sending_without_reply: true },
          reply_markup, disable_notification: true,
        });
      } catch {
        cta = await api(token, "sendMessage", {
          chat_id: channel, message_thread_id: threadId,
          text: "Подробности, актуальность и запись на просмотр",
          reply_markup, disable_notification: true,
        });
      }
      ctaMessageId = Number(cta.message_id);
      messageIds = albumIds;
      mode = "album";
    } catch (error) {
      for (const id of albumIds) {
        try { await api(token, "deleteMessage", { chat_id: channel, message_id: id }); } catch {}
      }
      throw error;
    }
  } else if (photos.length === 1) {
    const result = await multipartApi(token, "sendPhoto", {
      chat_id: channel, message_thread_id: threadId, photo: "attach://photo", caption,
      parse_mode: "HTML", reply_markup, disable_notification: true,
    }, [{ field: "photo", photo: photos[0] }]);
    messageIds = [Number(result.message_id)];
    mode = "media";
  } else {
    const result = await api(token, "sendMessage", {
      chat_id: channel, message_thread_id: threadId, text: caption, parse_mode: "HTML",
      disable_web_page_preview: true, reply_markup, disable_notification: true,
    });
    messageIds = [Number(result.message_id)];
  }
  const now = new Date().toISOString();
  return {
    code: codeOf(item), sourceUrl: item.sourceUrl, status: "active",
    textHash: hash(caption), photoHash: hash([MEDIA_VERSION, candidateUrls.slice(0, PREVIEW_PHOTO_LIMIT)]),
    leadHash: hash(`${CTA_VERSION}|${bot}|${startPayload(item)}`),
    messageIds, ctaMessageId, threadId, mode, caption, updatedAt: now, botUsername: bot,
  };
}
async function editApi(token: string, method: string, payload: Record<string, unknown>): Promise<any> {
  try { return await api(token, method, payload); }
  catch (error) {
    if (/message is not modified/i.test(String(error))) return null;
    throw error;
  }
}
async function editCaption(token: string, channel: string, entry: Entry, caption: string, item: Item, bot: string, leadUrl?: string, shareLeadUrl?: string) {
  const first = entry.messageIds[0];
  if (!first) return;
  const lead = leadUrl || `https://t.me/${bot.replace(/^@/, "")}?start=${startPayload(item)}`;
  const shareTarget = shareLeadUrl || lead;
  const share = `https://t.me/share/url?url=${encodeURIComponent(shareTarget)}`;
  const reply_markup = { inline_keyboard: [[
    { text: "Узнать подробнее", url: lead },
    { text: "Поделиться", url: share },
  ]] };
  if (entry.mode === "album") {
    await editApi(token, "editMessageCaption", { chat_id: channel, message_id: first, caption, parse_mode: "HTML" });
    if (entry.ctaMessageId) {
      await editApi(token, "editMessageText", {
        chat_id: channel, message_id: entry.ctaMessageId,
        text: "Подробности, актуальность и запись на просмотр", reply_markup,
      });
    }
  } else if (entry.mode === "media") {
    await editApi(token, "editMessageCaption", { chat_id: channel, message_id: first, caption, parse_mode: "HTML", reply_markup });
  } else {
    await editApi(token, "editMessageText", {
      chat_id: channel, message_id: first, text: caption, parse_mode: "HTML",
      disable_web_page_preview: true, reply_markup,
    });
  }
}
async function deleteEntryMessages(token: string, channel: string, entry: Entry) {
  const ids = [...(entry.messageIds || []), ...(entry.ctaMessageId ? [entry.ctaMessageId] : [])];
  for (const messageId of ids) {
    try {
      await api(token, "deleteMessage", { chat_id: channel, message_id: messageId });
    } catch (error) {
      const text = String(error);
      if (!/message to delete not found|message identifier is not specified/i.test(text)) throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 120));
  }
}

async function editLeadLink(token: string, channel: string, entry: Entry, item: Item, bot: string, leadUrl?: string, shareLeadUrl?: string) {
  const first = entry.messageIds[0];
  if (!first) return;
  const lead = leadUrl || `https://t.me/${bot.replace(/^@/, "")}?start=${startPayload(item)}`;
  const shareTarget = shareLeadUrl || lead;
  const share = `https://t.me/share/url?url=${encodeURIComponent(shareTarget)}`;
  const reply_markup = { inline_keyboard: [[
    { text: "Узнать подробнее", url: lead },
    { text: "Поделиться", url: share },
  ]] };
  if (entry.mode === "album" && entry.ctaMessageId) {
    await editApi(token, "editMessageText", {
      chat_id: channel, message_id: entry.ctaMessageId,
      text: "Подробности, актуальность и запись на просмотр", reply_markup,
    });
  } else {
    await editApi(token, "editMessageReplyMarkup", {
      chat_id: channel, message_id: first, reply_markup,
    });
  }
}
async function readJson<T>(file: string, fallback: T): Promise<T> {
  try { return JSON.parse(await fs.readFile(file, "utf8")) as T; } catch { return fallback; }
}
async function saveState(state: State) {
  await fs.mkdir(path.dirname(STATE_FILE), { recursive: true });
  const tmp = `${STATE_FILE}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2));
  await fs.rename(tmp, STATE_FILE);
}
async function main() {
  const apply = process.argv.includes("--apply");
  const migrateBotOwnership = process.argv.includes("--migrate-bot-ownership");
  const useLegacyToken = process.argv.includes("--legacy-token");
  const deleteIdArg = process.argv.indexOf("--delete-message-id");
  const bootstrapOldestFirst = process.argv.includes("--bootstrap-oldest-first");
  const limitArg = process.argv.indexOf("--limit-new");
  const limitNew = limitArg >= 0 ? Number(process.argv[limitArg + 1] || "0") : 0;
  const onlyArg = process.argv.indexOf("--only-codes");
  const onlyCodes = new Set(onlyArg >= 0 ? String(process.argv[onlyArg + 1] || "").split(",").map(x => x.trim()).filter(Boolean) : []);
  const cfg = parseEnv(await fs.readFile(CONFIG_FILE, "utf8"));
  const crm = parseEnv(await fs.readFile(CRM_ENV, "utf8"));
  const growthEnv = parseEnv(await fs.readFile(GROWTH_ENV, "utf8").catch(() => ""));
  const growth: GrowthConfig | undefined = growthEnv.SERVICE_KEY ? {
    url: cfg.GROWTH_CORE_URL || "http://127.0.0.1:8040",
    key: growthEnv.SERVICE_KEY,
    tenant: cfg.GROWTH_CORE_TENANT || "lebleu",
  } : undefined;
  const channel = cfg.TELEGRAM_CHANNEL || "";
  const bot = cfg.TELEGRAM_BOT_USERNAME || crm.LEBLEU_TELEGRAM_BOT_USERNAME || "FiodorCRMControlBot";
  const legacyToken = crm.TELEGRAM_BOT_TOKEN || "";
  const token = useLegacyToken ? legacyToken : (crm.LEBLEU_TELEGRAM_BOT_TOKEN || legacyToken);
  if (!channel) throw new Error(`Set TELEGRAM_CHANNEL in ${CONFIG_FILE}`);
  if (!token) throw new Error("Le Bleu Telegram bot token is missing");
  if (deleteIdArg >= 0) {
    const id = Number(process.argv[deleteIdArg + 1] || "0");
    if (!id) throw new Error("Invalid --delete-message-id");
    await api(token, "deleteMessage", { chat_id: channel, message_id: id });
    console.log(JSON.stringify({ deleted: id, channel }));
    return;
  }

  const items = await readJson<Item[]>(CATALOG, []);
  const topicMap = await readJson<Record<string, { name?: string; message_thread_id: number }>>(TOPICS_FILE, {});
  const qualityContent = await readJson<Record<string, QualityContent>>(QUALITY_CONTENT_FILE, {});
  const failures = await readJson<Array<{ url: string }>>(FAILURES, []);
  const failed = new Set(failures.map(x => x.url));
  const previous = await readJson<State>(STATE_FILE, { channel, entries: {} });
  if (previous.channel && previous.channel !== channel && Object.keys(previous.entries).length) {
    throw new Error(`State belongs to ${previous.channel}, configured channel is ${channel}`);
  }
  const state: State = { channel, entries: previous.entries || {} };
  const current = new Map(items.map(x => [x.sourceUrl, x]));
  let created = 0, changed = 0, photosChanged = 0, removed = 0, unchanged = 0, blocked = 0, errors = 0;
  const actions: string[] = [];
  const orderedItems = bootstrapOldestFirst ? [...items].reverse() : items;
  for (const item of orderedItems) {
    if (onlyCodes.size && !onlyCodes.has(codeOf(item))) continue;
    const rawQ = qualityContent[item.sourceUrl];
    const q = rawQ && rawQ.sourceFingerprint === item.sourceFingerprint ? rawQ : undefined;
    const reasons = qualityReasons(item, q);
    if (reasons.length) {
      actions.push(`BLOCK ${codeOf(item)} ${reasons.join(",")}`);
      blocked += 1;
      continue;
    }
    const key = item.sourceUrl;
    const code = codeOf(item);
    const topicKey = forumTopicKey(item, q);
    if (!topicKey) {
      actions.push(`BLOCK ${code} unclassified_property_type:${effectiveType(item, q) || "unknown"}`);
      blocked += 1;
      continue;
    }
    const desiredThreadId = Number(topicMap[topicKey]?.message_thread_id || 0);
    if (!desiredThreadId) {
      actions.push(`BLOCK ${code} missing_forum_topic:${topicKey}`);
      blocked += 1;
      continue;
    }
    const caption = render(item, bot, q);
    if (!q) actions.push(`TEXT_FALLBACK ${code} no_current_reviewed_copy`);
    const textHash = hash(caption);
    const photoHash = hash([MEDIA_VERSION, (item.imageUrls || []).slice(0, PREVIEW_PHOTO_LIMIT)]);
    const desiredMode: "album" | "media" | "text" = (item.imageUrls || []).length >= 2 ? "album" : (item.imageUrls || []).length === 1 ? "media" : "text";
    const leadInfo = await trackedLead(item, bot, growth);
    const shareInfo = await trackedLead(item, bot, growth, {
      source: "telegram_share",
      medium: "earned",
      campaign: "property_share",
      content: "listing",
      placement: "share_button",
    });
    const leadHash = hash(`${CTA_VERSION}|${bot}|${leadInfo.marker}|${shareInfo.marker}`);
    const old = state.entries[key];
    if (!old) {
      if (limitNew > 0 && created >= limitNew) { unchanged += 1; continue; }
      actions.push(`NEW ${codeOf(item)} ${item.address || ""}`);
      if (apply) {
        try {
          const createdEntry = await postItem(token, channel, item, caption, bot, desiredThreadId, leadInfo.url, shareInfo.url);
          state.entries[key] = { ...createdEntry, leadHash };
          await saveState(state);
          console.log(`PROGRESS NEW ${code}`);
          await new Promise(resolve => setTimeout(resolve, 500));
        } catch (error) {
          errors += 1;
          actions.push(`ERROR ${code} ${String(error)}`);
          console.error(`ITEM_ERROR ${code} ${String(error)}`);
          continue;
        }
      }
      created += 1;
      continue;
    }
    const oldBot = old.botUsername || "FiodorCRMControlBot";
    const ownerMigration = migrateBotOwnership && oldBot.replace(/^@/, "").toLowerCase() !== bot.replace(/^@/, "").toLowerCase();
    if (old.status === "removed" || old.photoHash !== photoHash || old.mode !== desiredMode || old.threadId !== desiredThreadId || ownerMigration) {
      actions.push(`REPOST ${codeOf(item)} ${ownerMigration ? "bot ownership changed" : "media/status/topic changed"}`);
      if (apply) {
        try {
          const replacement = await postItem(token, channel, item, caption, bot, desiredThreadId, leadInfo.url, shareInfo.url);
          const deleteToken = oldBot.replace(/^@/, "").toLowerCase() === bot.replace(/^@/, "").toLowerCase() ? token : legacyToken;
          try {
            await deleteEntryMessages(deleteToken, channel, old);
          } catch (deleteError) {
            // Roll back the replacement if the old publication could not be removed.
            // Otherwise state would point only to the new copy and the old one would
            // become an untracked duplicate in the public channel.
            try { await deleteEntryMessages(token, channel, replacement); } catch {}
            throw deleteError;
          }
          state.entries[key] = { ...replacement, leadHash };
          await saveState(state);
          console.log(`PROGRESS REPOST ${code}`);
          await new Promise(resolve => setTimeout(resolve, 500));
        } catch (error) {
          errors += 1;
          actions.push(`ERROR ${code} ${String(error)}`);
          console.error(`ITEM_ERROR ${code} ${String(error)}`);
          continue;
        }
      }
      photosChanged += 1;
    } else if (old.textHash !== textHash) {
      actions.push(`EDIT ${codeOf(item)} text/price changed`);
      if (apply) {
        try {
          await editCaption(token, channel, old, caption, item, bot, leadInfo.url, shareInfo.url);
          state.entries[key] = { ...old, caption, textHash, leadHash, status: "active", updatedAt: new Date().toISOString() };
          await saveState(state);
          console.log(`PROGRESS EDIT ${code}`);
        } catch (error) {
          errors += 1;
          actions.push(`ERROR ${code} ${String(error)}`);
          console.error(`ITEM_ERROR ${code} ${String(error)}`);
          continue;
        }
      }
      changed += 1;
    } else if (old.leadHash !== leadHash) {
      actions.push(`RELINK ${codeOf(item)} CTA bot changed`);
      if (apply) {
        try {
          await editLeadLink(token, channel, old, item, bot, leadInfo.url, shareInfo.url);
          state.entries[key] = { ...old, leadHash, updatedAt: new Date().toISOString() };
          await saveState(state);
          console.log(`PROGRESS RELINK ${code}`);
          await new Promise(resolve => setTimeout(resolve, 250));
        } catch (error) {
          errors += 1;
          actions.push(`ERROR ${code} ${String(error)}`);
          console.error(`ITEM_ERROR ${code} ${String(error)}`);
          continue;
        }
      }
      changed += 1;
    } else unchanged += 1;
  }
  for (const [key, old] of Object.entries(state.entries)) {
    if (current.has(key) || old.status === "removed" || failed.has(key)) continue;
    actions.push(`REMOVE ${old.code}`);
    if (apply) {
      await deleteEntryMessages(token, channel, old);
      state.entries[key] = {
        ...old,
        status: "removed",
        messageIds: [],
        ctaMessageId: undefined,
        updatedAt: new Date().toISOString(),
      };
      await saveState(state);
    }
    removed += 1;
  }

  console.log(JSON.stringify({ apply, channel, inventory: items.length, failures: failures.length,
    created, changed, photosChanged, removed, unchanged, blocked, errors }, null, 2));
  for (const line of actions.slice(0, 30)) console.log(line);
  if (actions.length > 30) console.log(`... ${actions.length - 30} more actions`);
  if (apply && errors > 0) process.exitCode = 2;
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
