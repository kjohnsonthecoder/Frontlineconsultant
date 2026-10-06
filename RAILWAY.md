# Railway deployment

Use the existing Dockerfile with Node 24. Configure the service through the Railway connected app: Dockerfile builder, healthcheck `/health`, 60-second health timeout, one replica, sleeping disabled, restart on failure. `/health` returns only status after checking SQLite; `/v1/health` remains authenticated for Base44.

Mount a private persistent volume at `/data` before deployment. Set `PORT=8080`, `FRONTLINE_DB_PATH=/data/frontline.sqlite`, `FRONTLINE_ALLOWED_HOSTS=frontlineconsultant.com`, and `NODE_ENV=production`. Generate `FRONTLINE_API_TOKEN` privately and store the matching value in Railway and Base44 backend secrets. Never commit secrets.

Project: 59b5f725-491e-4acc-bbd7-a0d3402eb827
Production environment: e834d382-8a93-470a-a153-189ed702015b

Deployment is pending a confirmed GitHub repository or published Docker image. No live service URL or live health verification exists yet. The Railway connected app cannot upload local source. Railway CLI is not installed or authenticated locally.

After deployment, generate the HTTPS domain and verify `/health` plus authenticated `/v1/health`. Set Base44 `FRONTLINE_API_URL` to the HTTPS origin and `FRONTLINE_API_TOKEN` to the matching secret, then verify bridge status without starting a scan.

Use service settings rather than a legacy railway.json: current Railway documentation deprecates legacy config-as-code for new services. The Dockerfile remains the build definition.
