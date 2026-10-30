import * as cheerio from "cheerio";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { extractListing, type ExtractedListing } from "../lib/extract-listing";

const BASE = "https://www.lebleu.com.ar";
const CATALOG_URL = `${BASE}/propiedades`;
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const DEFAULT_OUT = "/opt/listing-bridge/lebleu";
const AGENCY = "Le Bleu Negocios Inmobiliarios";
const SOURCE_ID = "lebleu";

type LeBleuItem = ExtractedListing & {
  sourceAgency: string;
  sourceId: string;
  sourceLocalId?: string;
  sourceUrl: string;
  slug: string;
  code?: string;
  operation?: string;
  propertyType?: string;
  latitude?: number;
  longitude?: number;
  sourceFingerprint: string;
  ruContentFingerprint: string;
  services: string[];
  environments: string[];
  comforts: string[];
};

function tidy(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}
function normalizeUrl(raw: string, base = BASE): string | undefined {
  try {
    const u = new URL(raw, base);
    if (u.hostname !== "www.lebleu.com.ar" && u.hostname !== "lebleu.com.ar") return;
    u.protocol = "https:";
    u.hostname = "www.lebleu.com.ar";
    u.hash = "";
    return u.toString();
  } catch {
    return;
  }
}

async function fetchHtml(url: string): Promise<string> {
  const headers: Record<string,string> = {
    "user-agent": UA,
    accept: "text/html,application/xhtml+xml",
    "accept-language": "es-AR,es;q=0.9,en;q=0.7",
    referer: BASE + "/",
    "cache-control": "no-cache",
  };
  let response = await fetch(url, { redirect: "follow", headers });
  // Le Bleu occasionally returns a transient 403 to a cold session. Warm the
  // first-party session and retry once instead of silently losing the listing.
  if (response.status === 403 || response.status === 429) {
    const warm = await fetch(BASE + "/", { redirect: "follow", headers }).catch(() => null);
    const cookie = warm?.headers.get("set-cookie")?.split(";")[0];
    response = await fetch(url, {
      redirect: "follow",
      headers: { ...headers, ...(cookie ? { cookie } : {}) },
    });
  }
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
  const html = await response.text();
  if (html.length < 1000 || !/<body[\s>]/i.test(html)) throw new Error(`Incomplete HTML for ${url}`);
  return html;
}
function visibleLines(html: string): string[] {
  const $ = cheerio.load(html);
  const body = $("body").clone();
  body.find("script,style,noscript,template,header,nav,footer,form,aside").remove();
  body.find("br").replaceWith("\n");
  body.find("div,p,h1,h2,h3,li,span,td,th").each((_i, el) => {
    $(el).prepend("\n").append("\n");
  });
  return body
    .text()
    .split(/[\r\n]+/)
    .map(tidy)
    .filter(Boolean);
}

function section(lines: string[], startLabel: RegExp, stopLabels: RegExp[]): string[] {
  const start = lines.findIndex((x) => startLabel.test(x));
  if (start < 0) return [];
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (stopLabels.some((rx) => rx.test(lines[i]))) break;
    out.push(lines[i]);
  }
  return out;
}
function cleanDescription(raw: string | undefined): string | undefined {
  if (!raw) return;
  let text = raw;
  text = text.replace(/https?:\/\/\S+|www\.\S+/gi, " ");
  text = text.replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, " ");
  text = text.replace(/\+?\d[\d\s().-]{7,}\d/g, " ");
  text = text.replace(/\b(?:WhatsApp|Wsp|Tel[eé]fono|Celular|Contacto)\b\s*:?\s*[^.;\n]{0,80}/gi, " ");
  text = text.replace(/Le Bleu Negocios Inmobiliarios/gi, " ");
  text = text.replace(/\bCOD\s+PROP\s+[A-Z0-9._/-]+/gi, " ");
  // Drop agency/legal boilerplate that is not information about the property.
  text = text.replace(/(?:las|todas las)\s+medidas(?:,| y)?\s*(?:superficies)?[^.]{0,260}(?:aproximad|orientativ|escritura)[^.]*\.?/gi, " ");
  text = text.replace(/(?:corredor\s+(?:inmobiliario|responsable|p[úu]blico|matriculado)|martillero(?:\s+p[úu]blico)?|matr[ií]cula\s*(?:n[°ºo.]*)?|cucicba\s*(?:n[°ºo.]*)?)[^.;]{0,180}[.;]?/gi, " ");
  // A number of Le Bleu descriptions are stored upstream as one malformed text
  // node ("18En...", "M2Las...", "pisoContrafrente..."). Rebuild only obvious
  // semantic boundaries; this changes punctuation, never property facts.
  text = text.replace(/([.!?])(?=[A-ZÁÉÍÓÚÑ])/g, "$1 ");
  text = text.replace(/\b(m2|m²)(?=(?:En|El|La|Las|Los|Se|Su|Cuenta|Superficie|Expensas)\b)/gi, "$1. ");
  const boundaryWords = "En|El|La|Las|Los|Se|Su|Cuenta|Superficie|Ambientes|Dormitorios|Baños|Cocheras|Expensas|Contrafrente|Cocina|Baño|Conexión|Calefacción|Pisos|Placard|Ventilación|Apto|Descripción|Living|Comedor|Dormitorio|Terraza|Balcón|Parrilla|Pileta|Piscina|Toilette|Lavadero|Quincho";
  text = text.replace(new RegExp(`(?<=[a-záéíóúñ0-9])(?=(?:${boundaryWords})\\b)`, "g"), ". ");
  text = text.replace(/\s+/g, " ").trim();
  return text || undefined;
}

function descriptionFromLeBleu(lines: string[]): string | undefined {
  const parts = section(lines, /^Descripci[oó]n$/i, [
    /^Le Bleu Negocios Inmobiliarios$/i,
    /^COD PROP\b/i,
    /^Caracter[ií]sticas Generales$/i,
  ]);
  const filtered = parts.filter((x) => !/^OFRECEMOS?\s+FINANCIAMIENTO/i.test(x));
  const joined = filtered
    .map((x) => /[.!?;:]$/.test(x) ? x : `${x}.`)
    .join(" ");
  return cleanDescription(joined);
}
function leBleuCoordinates(html: string): { latitude?: number; longitude?: number } {
  // Le Bleu embeds exact listing coordinates in the Google static-map URL.
  // Keep these as enrichment metadata only: they deliberately do NOT enter the
  // sourceFingerprint below, otherwise adding geospatial enrichment would make
  // every existing listing look materially changed and invalidate reviewed copy.
  const staticMap = html.match(/staticmap\?center=(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/i);
  if (staticMap) {
    const latitude = Number(staticMap[1]);
    const longitude = Number(staticMap[2]);
    if (Number.isFinite(latitude) && Number.isFinite(longitude)) return { latitude, longitude };
  }
  const streetView = html.match(/position\s*:\s*\{\s*lat\s*:\s*(-?\d+(?:\.\d+)?)\s*,\s*lng\s*:\s*(-?\d+(?:\.\d+)?)/i);
  if (streetView) {
    const latitude = Number(streetView[1]);
    const longitude = Number(streetView[2]);
    if (Number.isFinite(latitude) && Number.isFinite(longitude)) return { latitude, longitude };
  }
  return {};
}

function leBleuPhotos(html: string): string[] {
  const rx = /https:\/\/d1bsvyfhz28l2h\.cloudfront\.net\/[^"'<>\s]+?-(watermarked|thumbnail)\.jpg/gi;
  const byId = new Map<string, { url: string; rank: number; order: number }>();
  let order = 0;
  for (const match of html.matchAll(rx)) {
    const url = match[0].replace(/&amp;/g, "&");
    const idMatch = url.match(/cloudfront\.net\/([^/]+)\//i);
    const id = idMatch?.[1] ?? url;
    const rank = /-watermarked\.jpg$/i.test(url) ? 2 : 1;
    const current = byId.get(id);
    if (!current) byId.set(id, { url, rank, order: order++ });
    else if (rank > current.rank) byId.set(id, { ...current, url, rank });
  }
  return [...byId.values()]
    .sort((a, b) => a.order - b.order)
    .map((x) => x.url);
}

function findCode(lines: string[]): string | undefined {
  const hit = lines.find((x) => /^COD PROP\b/i.test(x));
  return hit?.replace(/^COD PROP\s*/i, "").trim() || undefined;
}
function findOperation(lines: string[]): string | undefined {
  const direct = lines.find((x) => /^(Venta|Alquiler|Alquiler temporario)$/i.test(x));
  if (direct) return direct;
  if (lines.slice(0, 30).some((x) => /^En Pozo$/i.test(x))) return "Venta";
  return;
}
function operationFromUrl(url: string): string | undefined {
  const slug = slugFromUrl(url).toLowerCase();
  if (slug.includes('alquiler')) return 'Alquiler';
  if (slug.includes('venta')) return 'Venta';
  return;
}
function propertyTypeFromUrl(url: string): string | undefined {
  const slug = slugFromUrl(url).toLowerCase();
  if (/departamento|dpto|monoambiente/.test(slug)) return 'Departamento';
  if (/casa/.test(slug)) return 'Casa';
  if (/ph/.test(slug)) return 'PH';
  if (/terreno|lote/.test(slug)) return 'Terreno';
  if (/local/.test(slug)) return 'Local Comercial';
  if (/oficina/.test(slug)) return 'Oficina';
  if (/cochera/.test(slug)) return 'Cochera';
  if (/galpon|deposito/.test(slug)) return 'Depósito';
  return;
}

function findPropertyType(lines: string[], operation?: string): string | undefined {
  const types = /^(Departamento|Casa|PH|Terreno|Terreno o Lote|Local Comercial|Oficina|Cochera|Dep[oó]sito)$/i;
  const start = operation ? lines.findIndex((x) => x === operation) : 0;
  return lines.slice(Math.max(0, start), Math.max(0, start) + 15).find((x) => types.test(x));
}

function numberFromText(raw: string | undefined): number | undefined {
  if (!raw) return;
  const m = raw.match(/([\d]+(?:[.,][\d]+)?)/);
  if (!m) return;
  const n = Number(m[1].replace(',', '.'));
  return Number.isFinite(n) ? n : undefined;
}

function leBleuCharacteristics(lines: string[]): Partial<ExtractedListing['details']> {
  const start = lines.findIndex((x) => /^Caracter[ií]sticas Generales$/i.test(x));
  if (start < 0) return {};
  const out: Partial<ExtractedListing['details']> = {};
  for (const line of lines.slice(start + 1, start + 25)) {
    let m;
    if ((m = line.match(/^Superficie total:\s*([\d.,]+)/i))) out.totalAreaM2 = numberFromText(m[1]);
    else if ((m = line.match(/^Superficie cubierta:\s*([\d.,]+)/i))) out.coveredAreaM2 = numberFromText(m[1]);
    else if ((m = line.match(/^Dormitorios:\s*(\d+)/i))) out.bedrooms = Number(m[1]);
    else if ((m = line.match(/^Ambientes:\s*(\d+)/i))) out.rooms = Number(m[1]);
    else if ((m = line.match(/^Baños:\s*(\d+)/i))) out.bathrooms = Number(m[1]);
    else if ((m = line.match(/^Cocheras:\s*(\d+)/i))) out.parkingSpaces = Number(m[1]);
    else if (/^Cocheras:\s*(?:No dispone|Sin cocheras?)/i.test(line)) out.parkingSpaces = 0;
    if (/^(Ambientes|Fotos|Ubicaci[oó]n)$/i.test(line)) break;
  }
  return out;
}


function leBleuFeatures(lines: string[]): string[] {
  const start = lines.findIndex((x) => /^Ambientes$/i.test(x));
  const end = start >= 0 ? lines.findIndex((x, i) => i > start && /^Fotos$/i.test(x)) : -1;
  const pool = start >= 0 ? lines.slice(start + 1, end > start ? end : start + 45) : [];
  const allowed = [
    'Balcón', 'Terraza', 'Parrilla', 'Piscina', 'Pileta', 'Patio', 'Jardín',
    'SUM', 'Laundry', 'Solarium', 'Aire Acondicionado', 'Calefacción',
    'Baulera', 'Cochera', 'Quincho', 'Gimnasio', 'Seguridad 24', 'Ascensor',
  ];
  const found: string[] = [];
  for (const feature of allowed) {
    if (pool.some((line) => line.toLocaleLowerCase('es-AR') === feature.toLocaleLowerCase('es-AR'))) found.push(feature);
  }
  const header = lines.slice(0, 28).join(' ');
  if (/\bapto cr[eé]dito\b/i.test(header) && !/\bno apto cr[eé]dito\b/i.test(header)) found.push('Apto crédito');
  return found;
}


function leBleuSectionValues(lines: string[], label: RegExp): string[] {
  const headings = /^(Caracter[ií]sticas Generales|Ambientes|Servicios|Comodidades|Fotos|Ubicaci[oó]n|Propiedades similares)$/i;
  const start = lines.findIndex((x) => label.test(x));
  if (start < 0) return [];
  const out: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (headings.test(line)) break;
    if (line && !out.includes(line)) out.push(line);
  }
  return out;
}

function leBleuAdditionalInfo(lines: string[]): Record<string,string> {
  const out: Record<string,string> = {};
  for (const line of leBleuSectionValues(lines, /^Caracter[ií]sticas Generales$/i)) {
    const m = line.match(/^([^:]{2,60}):\s*(.+)$/);
    if (!m) continue;
    const key = tidy(m[1]);
    const value = tidy(m[2]).replace(/\s+m2$/i, " m²");
    if (key && value) out[key] = value;
  }
  const header = lines.slice(0, 35).join(" ");
  if (/\bno apto cr[eé]dito\b/i.test(header)) out["Apto crédito"] = "No";
  else if (/\bapto cr[eé]dito\b/i.test(header)) out["Apto crédito"] = "Sí";
  return out;
}

function leBleuListSection(lines: string[], label: RegExp): string[] {
  return leBleuSectionValues(lines, label)
    .map(tidy)
    .filter((x) => x.length > 1 && x.length < 120 && !x.includes(":"));
}

function leBleuServices(lines: string[]): string[] {
  // Some older Le Bleu pages place the site's navigation/taxonomy immediately
  // after a "Servicios" heading. Those are website links, not property services.
  const siteNoise = /^(?:Inversión inmobiliaria|Tasaciones inmobiliarias|Propiedades|Departamentos en |Departamentos a estrenar|Otras Propiedades|Emprendimientos(?:\b| en | Terminados)|Otros emprendimientos|Copyright|Desarrollado por|Data Fiscal)/i;
  return leBleuListSection(lines, /^Servicios$/i).filter((x) => !siteNoise.test(x));
}

function findLeBleuPrice(lines: string[]): { amount?: string; currency?: string } {
  const idx = lines.findIndex((x) => /^Precio$/i.test(x));
  const pool = idx >= 0 ? lines.slice(idx + 1, idx + 5) : lines;
  for (const line of pool) {
    const m = line.match(/^(?:u\$s|us\$|usd)\s*([\d.]+(?:,[\d]+)?)/i);
    if (m) return { amount: m[1].replace(/\./g, '').replace(',', '.'), currency: 'USD' };
    const a = line.match(/^\$\s*([\d.]+(?:,[\d]+)?)/);
    if (a) return { amount: a[1].replace(/\./g, '').replace(',', '.'), currency: 'ARS' };
  }
  return {};
}

function findPrimaryAddress(lines: string[], operation?: string): string | undefined {
  const loc = lines.findIndex((x) => /^Ubicaci[oó]n$/i.test(x));
  if (loc >= 0) {
    for (const line of lines.slice(loc + 1, loc + 6)) {
      if (/^(Departamento|Casa|PH|Terreno|Terreno o Lote|Local Comercial|Oficina|Cochera|Dep[oó]sito)$/i.test(line)) continue;
      if (/^(Venta|Alquiler|Alquiler temporario)$/i.test(line)) continue;
      if (line.length >= 4 && line.length <= 180) return line;
    }
  }
  const start = operation ? lines.findIndex((x) => x === operation) : 0;
  const candidates = lines.slice(Math.max(0, start), Math.max(0, start) + 18);
  return candidates.find((x) => {
    if (x.length < 4 || x.length > 180) return false;
    if (/^(Venta|Alquiler|Departamento|Casa|PH|Terreno|Local|Oficina|Cochera)$/i.test(x)) return false;
    if (/\b(?:Ambientes?|bañ(?:o|os)|cocheras?|m2|m²|apto cr[eé]dito)\b/i.test(x)) return false;
    return /\d|\bal\s+\d/i.test(x);
  });
}

function slugFromUrl(url: string): string {
  return new URL(url).pathname.split("/").filter(Boolean).pop() || crypto.randomUUID();
}
async function extractLeBleu(url: string): Promise<LeBleuItem> {
  const html = await fetchHtml(url);
  const generic = extractListing(html, url);
  const lines = visibleLines(html);
  const operation = findOperation(lines) ?? operationFromUrl(url);
  const propertyType = findPropertyType(lines, operation) ?? propertyTypeFromUrl(url);
  const address = findPrimaryAddress(lines, operation) ?? generic.address;
  const specificDetails = leBleuCharacteristics(lines);
  const details = Object.keys(specificDetails).length
    ? {
        ...(generic.details.antiguedad !== undefined ? { antiguedad: generic.details.antiguedad } : {}),
        ...(generic.details.destacado !== undefined ? { destacado: generic.details.destacado } : {}),
        ...specificDetails,
      }
    : generic.details;
  const environments = leBleuListSection(lines, /^Ambientes$/i);
  const comforts = leBleuListSection(lines, /^Comodidades$/i);
  const services = leBleuServices(lines);
  const highlightedFeatures = [...new Set([...leBleuFeatures(lines), ...environments, ...comforts])];
  const additionalInfo = { ...generic.additionalInfo, ...leBleuAdditionalInfo(lines) };
  const exactPrice = findLeBleuPrice(lines);
  let description = descriptionFromLeBleu(lines) ?? cleanDescription(generic.description);
  if (description && details.rooms) {
    const head = description.match(/^Departamento\s+(\d+)\s+ambiente(?:s)?\b[,: -]*/i);
    if (head && Number(head[1]) !== details.rooms) description = tidy(description.slice(head[0].length));
  }
  const imageUrls = leBleuPhotos(html);
  const coordinates = leBleuCoordinates(html);
  const code = findCode(lines);
  const finalFeatures = highlightedFeatures.length ? highlightedFeatures : generic.highlightedFeatures;
  const ruRaw = JSON.stringify({
    operation,
    propertyType,
    address,
    description,
    details,
    highlightedFeatures: finalFeatures,
    additionalInfo,
    services,
    environments,
    comforts,
    expensesAmount: generic.expensesAmount,
    expensesCurrency: generic.expensesCurrency,
  });
  const raw = JSON.stringify({
    url,
    price: exactPrice.amount ?? generic.priceAmount,
    expenses: generic.expensesAmount,
    address,
    description,
    details,
    imageUrls,
  });
  return {
    ...generic,
    details,
    highlightedFeatures: finalFeatures,
    additionalInfo,
    services,
    environments,
    comforts,
    priceAmount: exactPrice.amount ?? generic.priceAmount,
    priceCurrency: exactPrice.currency ?? generic.priceCurrency,
    title: address ? `${propertyType ?? "Propiedad"} · ${address}` : generic.title,
    address,
    description,
    imageUrls: imageUrls.length ? imageUrls : generic.imageUrls,
    sourceAgency: AGENCY,
    sourceId: SOURCE_ID,
    sourceLocalId: code ? `${code}_${crypto.createHash("sha256").update(url).digest("hex").slice(0, 8)}` : undefined,
    sourceUrl: url,
    slug: slugFromUrl(url),
    code,
    operation,
    propertyType,
    ...coordinates,
    sourceFingerprint: crypto.createHash("sha256").update(raw).digest("hex"),
    ruContentFingerprint: crypto.createHash("sha256").update(ruRaw).digest("hex"),
  };
}
function money(amount?: string, currency?: string): string | undefined {
  if (!amount) return;
  const n = Number(amount);
  const value = Number.isFinite(n)
    ? new Intl.NumberFormat("es-AR", { maximumFractionDigits: 0 }).format(n)
    : amount;
  return `${currency === "USD" ? "USD" : currency || ""} ${value}`.trim();
}

function compactDescription(text?: string, max = 520): string | undefined {
  if (!text) return;
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const end = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf("; "));
  return (end > 240 ? cut.slice(0, end + 1) : cut).trimEnd() + "…";
}

function renderTelegram(item: LeBleuItem, cta: string): string {
  const d = item.details;
  const specs = [
    d.totalAreaM2 ? `${d.totalAreaM2} m²` : d.coveredAreaM2 ? `${d.coveredAreaM2} m² cub.` : undefined,
    d.rooms ? `${d.rooms} amb.` : undefined,
    d.bedrooms && d.rooms !== 1 ? `${d.bedrooms} dorm.` : undefined,
    d.bathrooms ? `${d.bathrooms} baño${d.bathrooms === 1 ? "" : "s"}` : undefined,
  ].filter(Boolean);
  const lines = [
    `🏠 ${item.operation ?? "Propiedad"} · ${item.propertyType ?? "Le Bleu"}`,
    item.address ? `📍 ${item.address}` : undefined,
    money(item.priceAmount, item.priceCurrency) ? `💵 ${money(item.priceAmount, item.priceCurrency)}` : undefined,
    specs.length ? `📐 ${specs.join(" · ")}` : undefined,
    item.expensesAmount ? `💳 Expensas: ${money(item.expensesAmount, item.expensesCurrency)}` : undefined,
    item.highlightedFeatures.length
      ? `✨ ${item.highlightedFeatures.slice(0, 6).join(" · ")}`
      : undefined,
    "",
    compactDescription(item.description),
    "",
    `🏢 ${AGENCY}`,
    item.code ? `Código: ${item.code}` : undefined,
    `📩 Consulta / visita: ${cta}`,
  ].filter((x): x is string => x !== undefined);
  return lines.join("\n").slice(0, 1020);
}

type TelegramCall = Record<string, unknown>;

function telegramPayloads(item: LeBleuItem, caption: string, chatId: string): TelegramCall[] {
  const photos = item.imageUrls.slice(0, 30);
  if (!photos.length) return [{ method: "sendMessage", chat_id: chatId, text: caption }];
  const calls: TelegramCall[] = [];
  for (let start = 0; start < photos.length; start += 10) {
    const chunk = photos.slice(start, start + 10);
    const media = chunk.map((photo, index) => ({
      type: "photo",
      media: photo,
      ...(start === 0 && index === 0 ? { caption } : {}),
    }));
    calls.push({ method: "sendMediaGroup", chat_id: chatId, media });
  }
  return calls;
}

async function catalogUrls(maxPages = 40): Promise<string[]> {
  const urls = new Set<string>();
  for (let page = 1; page <= maxPages; page += 1) {
    const html = await fetchHtml(page === 1 ? CATALOG_URL : `${CATALOG_URL}?page=${page}`);
    const $ = cheerio.load(html);
    let added = 0;
    $('a[href*="/propiedad/"]').each((_i, el) => {
      const normalized = normalizeUrl($(el).attr("href") ?? "");
      if (normalized && !urls.has(normalized)) {
        urls.add(normalized);
        added += 1;
      }
    });
    if (added === 0) break;
  }
  return [...urls];
}
async function poolMap<T, R>(values: T[], concurrency: number, fn: (value: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(values.length);
  let cursor = 0;
  async function worker() {
    for (;;) {
      const index = cursor++;
      if (index >= values.length) return;
      results[index] = await fn(values[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, () => worker()));
  return results;
}

async function saveItem(outRoot: string, item: LeBleuItem, cta: string, chatId: string) {
  const dir = path.join(outRoot, "items", item.code || item.slug);
  await fs.mkdir(dir, { recursive: true });
  const caption = renderTelegram(item, cta);
  const payloads = telegramPayloads(item, caption, chatId);
  await Promise.all([
    fs.writeFile(path.join(dir, "listing.json"), JSON.stringify(item, null, 2)),
    fs.writeFile(path.join(dir, "telegram.txt"), caption + "\n"),
    fs.writeFile(path.join(dir, "telegram_payload.json"), JSON.stringify(payloads, null, 2)),
  ]);
  return { caption, payloads };
}
function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const outRoot = argValue("--out") || DEFAULT_OUT;
  const cta = argValue("--cta") || "@LeBleuArgentinaBot";
  const chatId = argValue("--chat-id") || "@YOUR_CHANNEL";
  const one = argValue("--one");
  const limit = Number(argValue("--limit") || "0");
  const concurrency = Math.min(5, Math.max(1, Number(argValue("--concurrency") || "3")));
  await fs.mkdir(outRoot, { recursive: true });

  if (one) {
    const normalized = normalizeUrl(one);
    if (!normalized || !normalized.includes("/propiedad/")) throw new Error("--one must be a lebleu.com.ar property URL");
    const item = await extractLeBleu(normalized);
    const saved = await saveItem(outRoot, item, cta, chatId);
    console.log(saved.caption);
    console.log(`\nphotos=${item.imageUrls.length} calls=${saved.payloads.length} source=${item.sourceUrl}`);
    return;
  }

  const discovered = await catalogUrls();
  const selected = limit > 0 ? discovered.slice(0, limit) : discovered;
  console.log(`Le Bleu catalog discovered=${discovered.length} selected=${selected.length}`);
  // A transient source error must not make an active listing disappear from the
  // production catalogue. Reuse the last good snapshot for that URL and report
  // the failure so the next sync can retry it.
  const previousByUrl = new Map<string, LeBleuItem>();
  try {
    const previous = JSON.parse(await fs.readFile(path.join(outRoot, "catalog.json"), "utf8"));
    for (const row of previous) if (row?.sourceUrl) previousByUrl.set(String(row.sourceUrl), row);
  } catch {}
  const failures: Array<{ url: string; error: string; preserved?: boolean }> = [];
  const items = await poolMap(selected, concurrency, async (url, index) => {
    try {
      const item = await extractLeBleu(url);
      await saveItem(outRoot, item, cta, chatId);
      if ((index + 1) % 10 === 0 || index + 1 === selected.length) {
        console.log(`processed ${index + 1}/${selected.length}`);
      }
      return item;
    } catch (error) {
      const previous = previousByUrl.get(url);
      failures.push({
        url,
        error: error instanceof Error ? error.message : String(error),
        preserved: Boolean(previous),
      });
      return previous ?? null;
    }
  });
  const ok = items.filter((x): x is LeBleuItem => Boolean(x));
  const byOperation = ok.reduce<Record<string, number>>((acc, item) => {
    const key = item.operation || "Unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  await fs.writeFile(path.join(outRoot, "catalog.json"), JSON.stringify(ok, null, 2));
  await fs.writeFile(path.join(outRoot, "failures.json"), JSON.stringify(failures, null, 2));
  await fs.writeFile(
    path.join(outRoot, "summary.json"),
    JSON.stringify({ discovered: discovered.length, processed: ok.length, failures: failures.length, byOperation }, null, 2),
  );
  console.log(`done processed=${ok.length} failures=${failures.length}`);
  console.log(`operations=${JSON.stringify(byOperation)}`);
  console.log(`output=${outRoot}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
