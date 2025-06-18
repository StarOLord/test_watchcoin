/**
 * Import function triggers from their respective submodules:
 *
 * const {onCall} = require("firebase-functions/v2/https");
 * const {onDocumentWritten} = require("firebase-functions/v2/firestore");
 *
 * See a full list of supported triggers at https://firebase.google.com/docs/functions
 */


// Create and deploy your first functions
// https://firebase.google.com/docs/functions/get-started

// exports.helloWorld = onRequest((request, response) => {
//  logger.info("Hello logs!", {structuredData: true});
//  response.send("Hello from Firebase!");
// });

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");
const querystring = require("querystring");

admin.initializeApp();
const db = admin.firestore(); // Инициализация Firestore для админского доступа

// Получаем BOT_TOKEN из конфигурации окружения Firebase
// Запустите: firebase functions:config:set
// telegram.bot_token="YOUR_TELEGRAM_BOT_TOKEN"
const TELEGRAM_BOT_TOKEN = functions.config().telegram.bot_token;

if (!TELEGRAM_BOT_TOKEN) {
  console.error("TELEGRAM_BOT_TOKEN is not set in Firebase functions config!");
  // Это предотвратит развертывание функции, если токен не установлен
  throw new Error("TELEGRAM_BOT_TOKEN is not configured.");
}

/**
 * Проверяет целостность данных Telegram initData.
 * @param {Object} initData Объекты initData из Telegram.WebApp.initDataUnsafe.
 * @param {string} token Токен вашего Telegram-бота.
 * @return {boolean} True, если данные подлинные, иначе False.
 */
function checkTelegramInitData(initData, token) {
  // 1. Создаем строку данных для проверки хеша
  const dataCheckString = Object.keys(initData)
      .filter((key) => key !== "hash") // Исключаем сам хеш
      .sort() // Сортируем ключи по алфавиту
      .map((key) => `${key}=${initData[key]}`)
      .join("\n");

  // 2. Вычисляем секретный ключ (HMAC-SHA256)
  const secretKey = crypto.createHash("sha256").update(token).digest();

  // 3. Вычисляем хеш данных
  const hmac = crypto.createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

  // 4. Сравниваем вычисленный хеш с хешем из initData
  return hmac === initData.hash;
}

/**
 * Облачная функция для аутентификации пользователя Telegram в Firebase.
 * Она принимает initData из Telegram Mini App, проверяет ее подлинность
 * и выдает кастомный токен Firebase.
 */
exports.telegramAuth = functions.https.onCall(async (data, context) => {
  const initData = data.initData;

  if (!initData) {
    throw new functions.https.HttpsError(
        "invalid-argument",
        "initData is required.",
    );
  }

  // Декодируем query string, если initData приходит как string
  let parsedInitData;
  if (typeof initData === "string") {
    parsedInitData = querystring.parse(initData);
  } else {
    parsedInitData = initData; // Если уже объект
  }

  // Проверка подлинности данных Telegram
  if (!checkTelegramInitData(parsedInitData, TELEGRAM_BOT_TOKEN)) {
    throw new functions.https.HttpsError(
        "unauthenticated",
        "Invalid Telegram Init Data.",
    );
  }

  const telegramUser = parsedInitData.user ?
      JSON.parse(parsedInitData.user) : null;

  if (!telegramUser || !telegramUser.id) {
    throw new functions.https.HttpsError(
        "unauthenticated",
        "Telegram User ID not found in Init Data.",
    );
  }

  const uid = telegramUser.id.toString();

  try {
    // Создаем кастомный токен Firebase для этого UID
    const customToken = await admin.auth().createCustomToken(uid);

    // Опционально: Сохраняем или обновляем информацию
    // Это полезно для ведения списка пользователей или хранения доп. данных
    const userDocRef = db.collection("users").doc(uid);
    await userDocRef.set(
        {
          telegramId: uid,
          firstName: telegramUser.first_name || null,
          lastName: telegramUser.last_name || null,
          username: telegramUser.username || null,
          languageCode: telegramUser.language_code || null,
          photoUrl: telegramUser.photo_url || null,
          lastLogin: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true},
    );

    return {customToken: customToken};
  } catch (error) {
    console.error(
        "Error creating custom token or saving user data:",
        error,
    );
    throw new functions.https.HttpsError(
        "internal",
        "Unable to create custom token.",
        error.message,
    );
  }
});
