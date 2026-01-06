-- CreateTable
CREATE TABLE "UrlCheck" (
    "id" SERIAL NOT NULL,
    "originalUrl" TEXT NOT NULL,
    "finalUrl" TEXT,
    "verdict" TEXT NOT NULL,
    "score" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UrlCheck_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OpenPhishEntry" (
    "id" SERIAL NOT NULL,
    "url" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OpenPhishEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "OpenPhishEntry_url_key" ON "OpenPhishEntry"("url");
