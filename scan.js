'use strict';

const puppeteer = require('puppeteer');
const {TimeoutError} = puppeteer.errors;
const {URL} = require('url');
const log4js = require('log4js');
const readline = require('readline');
const tldjs = require('tldjs');
const dateFormat = require('dateformat');
const geolite2 = require('geolite2-redist');
const maxmind = require('maxmind');
const fs = require('fs');
const sqlite = require('sqlite');
const dbPromise = sqlite.open('./foo.db', { Promise });

let trackers = JSON.parse(fs.readFileSync('trackers.json', 'utf8'));

async function initDb() {
  const db = await dbPromise;
  await Promise.all([
      db.run(`CREATE TABLE IF NOT EXISTS crawl (
        crawl_id INTEGER PRIMARY KEY,
        start_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )`),
      db.run(`CREATE TABLE IF NOT EXISTS site_visits (
        visit_id INTEGER PRIMARY KEY,
        crawl_id INT NOT NULL,
        site_url TEXT NOT NULL,
        final_url TEXT,
        name TEXT NOT NULL,
        first_party_persistent_cookies INT DEFAULT 0,
        first_party_session_cookies INT DEFAULT 0,
        third_party_persistent_cookies INT DEFAULT 0,
        third_party_session_cookies INT DEFAULT 0,
        third_party_requests INT DEFAULT 0,
        insecure_requests INT DEFAULT 0,
        success INT DEFAULT 0,
        base_domain TEXT,
        time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        site_id INT NOT NULL,
        scheme TEXT
      )`),
      db.run(`CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY,
        crawl_id INT NOT NULL,
        visit_id INT NOT NULL,
        name TEXT,
        value TEXT,
        domain TEXT,
        path TEXT,
        expires TEXT,
        http_only INT,
        secure INT,
        same_site TEXT,
        session INT,
        base_domain TEXT,
        site_id INT NOT NULL
      )`),
      db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY,
        crawl_id INT NOT NULL,
        visit_id INT NOT NULL,
        url TEXT NOT NULL,
        headers TEXT NOT NULL,
        base_domain TEXT,
        scheme TEXT,
        request_id TEXT,
        method TEXT,
        resource_type TEXT,
        post_data TEXT,
        site_id INT NOT NULL
        )`),
      db.run(`CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY,
        crawl_id INT NOT NULL,
        visit_id INT NOT NULL,
        site_name TEXT,
        url TEXT NOT NULL,
        host TEXT,
        base_domain TEXT,
        headers TEXT,
        scheme TEXT,
        country TEXT,
        is_in_eu INT,
        disconnect_category TEXT,
        disconnect_name TEXT,
        ip TEXT,
        content TEXT,
        request_id TEXT,
        response_status INT,
        response_status_text TEXT,
        site_id INT NOT NULL
        )`),
      db.run(`CREATE TABLE IF NOT EXISTS site_trackers (
        id INTEGER PRIMARY KEY,
        site_id INT NOT NULL,
        site_name TEXT NOT NULL,
        disconnect_name TEXT NOT NULL,
        disconnect_category TEXT NOT NULL,
        url TEXT NOT NULL
        )`),
    ]);
  let statement = await db.run("INSERT INTO crawl DEFAULT VALUES");
  return new Promise(resolve => {
    resolve(statement.lastID);
  });
}

log4js.configure({
  appenders: {
    out: {type: 'stdout'},
    app: {type: 'file', filename: 'scan.log'},
  },
  categories: {
    default: {
      appenders: ['out', 'app'],
      level: 'info',
    },
  },
});

const logger = log4js.getLogger();

async function scanSite(crawl_id, site, db, lookup) {
  logger.info(`Scanning ${site.url}`);

  const timeout = 120000;
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--lang=sv-SE,se']
  });
  const viewport = {
    width: 1920,
    height: 1080,
  };

  let statement = await db.run('INSERT INTO site_visits (crawl_id, site_url, name, site_id) VALUES (?, ?, ?, ?)',
    crawl_id, site.url, site.name, site.site_id
    );
  const visit_id = statement.lastID;

  try {
    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();
    const client = await page.target().createCDPSession();

    await page.setViewport(viewport);
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36');

    const requests = [];
    page.on('request', (request) => {
      requests.push({
        'url': request.url(),
        'headers': request.headers(),
        'request_id': request._requestId,
        'method': request.method(),
        'resource_type': request.resourceType(),
        'post_data': request.postData()
      });
    });

    const responses = [];
    page.on('response', async response => {
      const status = response.status().valueOf();
      let content;
      let resourceType = response.request().resourceType();
      try {
        // https://github.com/puppeteer/puppeteer/issues/2176#issuecomment-434665348
        if (
            status
            && !(status > 299
            && status < 400)
            && !(status === 204)
            && !(resourceType === 'image')
            && !(resourceType === 'imageset')
            && !(resourceType === 'media')
            && !(resourceType === 'font')
            && !(resourceType === 'fetch')
        ) {
          content = await response.text()
        }
      } catch (err) {
        logger.warn("Error fetching data:");
        logger.warn(`Resourcetype: ${resourceType}`);
        logger.warn(err);
      }

      responses.push({
          'url': response.url(),
          'remote_address': response.remoteAddress(),
          'headers': response.headers(),
          'content': content,
          'request_id': response.request()._requestId,
          'status': status,
          'status_text': response.statusText()
        });
    });

    let pageResponse;
    for (const waitUntilSetting of [['domcontentloaded', 'networkidle2'], 'networkidle2', 'load']) {
      try {
        pageResponse = await page.goto(site.url, {
          waitUntil: waitUntilSetting,
          timeout: timeout,
        });
      } catch (err) {
        if (err instanceof TimeoutError) {
          logger.info(`${site.url} timed out`);
        } else {
          throw err;
        }
      }
    }
    if (pageResponse == null) {
      throw 'Page timeout';
    }

    await page.waitForTimeout(15000);

    let date_and_time = dateFormat(new Date(), 'yyyy-mm-dd_HHMMss');

    let screenshot_dir = `./screenshots/${crawl_id}`;
    if (!fs.existsSync(screenshot_dir)) {
      fs.mkdirSync(screenshot_dir, {recursive: true});
    }
    await page.screenshot({path: `./screenshots/${crawl_id}/${tldjs.parse(site.url).domain}-${site.site_id}-${date_and_time}-${visit_id}.cropped.png`, clip: {x: 0, y: 0, width: 1920, height: 1920}});

    // Necessary to get *ALL* cookies
    const cookies = await client.send('Network.getAllCookies');

    // let localStorage = await page.evaluate(() => { return {...localStorage}; });
    // ^- prettier, but we've got to truncate things for sanity:
    let localStorageData = {};
    try {
      localStorageData = await page.evaluate(() => {
        const tmpObj = {};
        const keys = Object.keys(localStorage);
        for (let i = 0; i < keys.length; ++i) {
          tmpObj[keys[i].substring(0, 100)] = localStorage.getItem(keys[i]).substring(0, 100);
        }
        return tmpObj;
      });
    } catch (err) {
      logger.warn(`Accessing localStorage failed. This shouldn't happen. Error:`);
      logger.warn(err);
    }

    const title = await page.title();
    const finalUrl = await page.url();
    const parsedUrl = new URL(finalUrl);
    const isValidUrl = tldjs.parse(parsedUrl.hostname).tldExists;

    let base_domain = tldjs.parse(finalUrl).domain;
    let scheme = parsedUrl.protocol.replace(':', '');

    let first_party_persistent_cookies = 0;
    let first_party_session_cookies = 0;
    let third_party_persistent_cookies = 0;
    let third_party_session_cookies = 0;

    for (const cookie of cookies.cookies) {
      let cookie_base_domain;
      if (cookie['domain'].startsWith('.')) {
        cookie_base_domain = tldjs.parse(cookie['domain'].substr(1)).domain;
      } else {
        cookie_base_domain = tldjs.parse(cookie['domain']).domain;
      }

      if (cookie_base_domain === base_domain && !cookie['session']) {
        first_party_persistent_cookies++;
      }
      if (cookie_base_domain === base_domain && cookie['session']) {
        first_party_session_cookies++;
      }
      if (cookie_base_domain !== base_domain && !cookie['session']) {
        third_party_persistent_cookies++;
      }
      if (cookie_base_domain !== base_domain && cookie['session']) {
        third_party_session_cookies++;
      }

      await db.run("INSERT INTO cookies (crawl_id, visit_id, name, value, domain, path, expires, http_only, secure, same_site, session, base_domain, site_id)" +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          crawl_id, visit_id, cookie['name'], cookie['value'], cookie['domain'], cookie['path'], cookie['expires'], cookie['httpOnly'], cookie['secure'],
          cookie['same_site'], cookie['session'], cookie_base_domain, site.site_id);
    }

    const responseHeaders = pageResponse.headers();
    const responseStatus = pageResponse.status();

    let third_party_requests = 0;
    let insecure_requests = 0;

    let success = 1;
    let results;
    if (responseStatus >= 200 && responseStatus <= 299 && isValidUrl) {
      if (responseHeaders['content-type'] && (responseHeaders['content-type'].startsWith('text/html') || responseHeaders['content-type'].startsWith('application/xhtml+xml'))) {
        for (const request of requests) {
          let request_base_domain = "";
          if (tldjs.parse(request.url).domain) {
            request_base_domain = tldjs.parse(request.url).domain;
          }

          let url_obj = new URL(request.url);
          await db.run(`INSERT INTO requests (crawl_id, visit_id, url, headers, scheme, request_id, method, resource_type, post_data, site_id, base_domain) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              crawl_id, visit_id, request.url, JSON.stringify(request.headers), url_obj.protocol, request.request_id,
              request.method, request.resource_type, request.post_data, site.site_id, request_base_domain);
        }

        for (const response of responses) {
          if (response.remote_address.ip) {
            let response_base_domain = "";
            if (tldjs.parse(response.url).domain) {
              response_base_domain = tldjs.parse(response.url).domain;
            }
            if (response_base_domain !== base_domain) {
              third_party_requests++;
            }
            let response_host = tldjs.parse(response.url).hostname;

            let url_obj = new URL(response.url);
            if (url_obj.protocol === "http:") {
              insecure_requests++;
            }

            let disconnect_category;
            let disconnect_name;

            if (trackers.hasOwnProperty(response_base_domain)) {
              disconnect_category = trackers[response_base_domain].category;
              disconnect_name = trackers[response_base_domain].name;
            }

            let geodata = lookup.get(response.remote_address.ip);
            let is_in_eu = 2;
            let iso_code = "UNKNOWN";
            if (geodata) {
              if ("country" in geodata && "is_in_european_union" in geodata.country) {
                is_in_eu = geodata.country.is_in_european_union ? 1 : 0;
                iso_code = geodata.country.iso_code;
              }
            }

            await db.run(`INSERT INTO responses
            (crawl_id, visit_id, site_name, url, host, base_domain, headers, scheme, country,
            is_in_eu, disconnect_category, disconnect_name, ip, content, request_id,
            response_status, response_status_text, site_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                crawl_id, visit_id, site.name, response.url, response_host, response_base_domain, JSON.stringify(response.headers), url_obj.protocol,
                iso_code, is_in_eu, disconnect_category, disconnect_name, response.remote_address.ip, response.content,
                response.request_id, response.status, response.status_text, site.site_id);
          }
        }
      } else {
        logger.warn(`Failed checking ${site.url}: ${responseStatus}`);
        success = 0;
      }
    } else {
      logger.warn(`Failed checking ${site.url}: ${responseStatus}`);
      success = 0;
    }

    await db.run(`UPDATE site_visits SET success = ?, final_url = ?, first_party_persistent_cookies = ?,
     first_party_session_cookies = ?, third_party_persistent_cookies = ?, third_party_session_cookies = ?,
     third_party_requests = ?, insecure_requests = ?, base_domain = ?, scheme = ? 
     WHERE visit_id = ?`,
        success, finalUrl, first_party_persistent_cookies, first_party_session_cookies,
        third_party_persistent_cookies, third_party_session_cookies, third_party_requests, insecure_requests,
        base_domain, scheme, visit_id);

    await context.close();
    logger.info(`Successfully checked ${site.url}`);
  } catch (err) {
    logger.warn(`Failed checking ${site.url}: ${err.toString()}`);
    logger.warn(`Failed: ${err.toString()}`);
    logger.warn(err.stack)
  }
  await browser.close();
  logger.info(`Finished with ${site.url}\n`);
}

async function checkTrackers(db) {
  logger.info(`Starting checkTrackers`);

  const result = await db.all(`SELECT site_id, site_name, base_domain, host, url FROM responses`);

  result.forEach(function (row) {
    let tracker_domain;
    if (trackers.hasOwnProperty(row['base_domain'])) {
      tracker_domain = row['base_domain'];
    }
    if (trackers.hasOwnProperty(row['domain'])) {
      tracker_domain = row['domain'];
    }

    if (tracker_domain) {
      //console.log(trackers[tracker_domain]);

      for (var disconnect_category of trackers[tracker_domain]['category']) {
        //console.log(`Category: ${disconnect_category}`);

        db.run(`INSERT INTO site_trackers (site_id, site_name, disconnect_name, disconnect_category, url) VALUES (?, ?, ?, ?, ?)`,
          row.site_id, row.site_name, trackers[tracker_domain].name,
          disconnect_category, row.url);
      }
    }
  });

  logger.info(`Finished checkTrackers`);
}

(async () => {
  const crawl_id = await initDb();
  logger.info(`Starting crawl ${crawl_id}`);
  const db = await dbPromise;
  await db.run('PRAGMA journal_mode = WAL;');

  let lookup = await geolite2.open('GeoLite2-Country', path => {
      return maxmind.open(path);
  });

  const fileStream = fs.createReadStream('sites.txt');
  const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
  });

  let i = 1;
  for await (const line of rl) {
    const [url, name] = line.split('|');
    await scanSite(crawl_id, {url: url, name: name, site_id: i}, db, lookup);
    ++i;
  }

  lookup.close();
  checkTrackers(db);
  await db.close();
})();
