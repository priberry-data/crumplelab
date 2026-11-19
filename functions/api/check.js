// The web app check moved to Greenlit (greenlit.priberry.com). This endpoint is retired: it answers 410 and does no
// work, so nothing here can be used to fetch other sites or fill up storage.
const gone = () =>
  new Response(JSON.stringify({ error: "The app check moved to https://greenlit.priberry.com" }), {
    status: 410,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=86400" },
  });

export const onRequest = gone;
