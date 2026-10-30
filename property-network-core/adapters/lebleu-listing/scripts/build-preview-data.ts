import fs from "node:fs/promises";

const root = "/opt/lebleu-listing-bridge/public/data";
const catalogPath = `${root}/full/catalog.json`;
const previewPath = `${root}/preview.json`;

async function main() {
  const items = JSON.parse(await fs.readFile(catalogPath, "utf8"));
  const preview = {
    generatedAt: new Date().toISOString(),
    items: items.map((item: any) => ({
      code: item.code,
      operation: item.operation,
      propertyType: item.propertyType,
      address: item.address,
      priceAmount: item.priceAmount,
      priceCurrency: item.priceCurrency,
      details: item.details || {},
      highlightedFeatures: item.highlightedFeatures || [],
      description: String(item.description || "").slice(0, 520),
      images: (item.imageUrls || []).slice(0, 6),
      sourceUrl: item.sourceUrl,
      fingerprint: item.sourceFingerprint,
    })),
  };
  await fs.writeFile(previewPath, JSON.stringify(preview));
  console.log(`preview items=${preview.items.length}`);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
