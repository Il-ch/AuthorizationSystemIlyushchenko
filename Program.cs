using System.Text;
using System.Security.Cryptography;

class Program
{
    const string UserFile = "Administration/nameuser.txt"; // Константи для файлів
    const string LogFile = "Administration/us_book.txt";
    const string EncryptedUserFile = "Administration/EncryptedUserAuthorizationData.xml";
    const int MaxUsers = 14; // Обмеження на кількість користувачів системи

    static void Main()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        InitializeUserFile();

        while (true)
        {
            Console.WriteLine("=== Головне меню ===");
            Console.WriteLine("1.Авторизація");
            Console.WriteLine("2.Вихід");
            Console.Write("Виберiть опцiю: ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    AuthorizeUser();
                    break;
                case "2":
                    Console.WriteLine("Вихiд з програми...");
                    return;
                default:
                    Console.WriteLine("Некоректний вибiр. Спробуйте ще раз.");
                    Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
                    Console.ReadKey();
                    Console.Clear();
                    break;
            }
        }
    }

    static (string Login, string Password, string AccessRights, string Directories) ParseUserData(string userData) // Метод для парсингу даних користувача
    {
        string[] parts = userData.Split(';');
        string login = parts[0].Split(':')[1].Trim();
        string password = parts[1].Split(':')[1].Trim();
        string accessRights = parts[2].Split(':')[1].Trim();
        string directories = parts[3].Split(':')[1].Trim();

        return (login, password, accessRights, directories);
    }

    static void InitializeUserFile() // Інiцiалiзацiя файлу користувачiв
    {
        if (!File.Exists(UserFile))
        {
            using (StreamWriter writer = new StreamWriter(UserFile))
            {
                writer.WriteLine("login: admin; password: admin123; accessRights: MAX; directories: MAX;");
            }
        }
    }

    static void AuthorizeUser() // Метод для авторизацiї
    {
        Console.Clear();
        Console.WriteLine("--- Авторизацiя ---");

        Console.Write("Логiн: ");
        string login = Console.ReadLine();

        Console.Write("Пароль: ");
        string password = Console.ReadLine();

        bool userFound = false;
        bool isAdmin = false;

        string[] users = File.ReadAllLines(UserFile); // Читання файлу користувачiв

        foreach (var user in users)
        {
            var data = ParseUserData(user);

            if (data.Login == login && data.Password == password) // Перевiрка логiну та паролю
            {
                userFound = true;

                LogAction(login, "Авторизація");

                if (data.AccessRights == "MAX") // Перевiрка, чи це адмiнiстратор
                {
                    isAdmin = true;
                    HandleAdminKeyFile(); // Перевірка наявності та створення файлу ключів
                    EncryptUserData(); // Шифрування даних користувачів
                }

                if (isAdmin)
                {
                    AdminMenu();
                }
                else
                {
                    UserMenu(login);
                }
                break;
            }
        }

        if (!userFound) // Якщо не знайдено користувача
        {
            Console.WriteLine("Невiрний логiн або пароль!");
            Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
            Console.ReadKey();
            Console.Clear();
        }
    }

    static void AdminMenu() // Меню адмiнiстратора
    {
        bool running = true;

        while (running)
        {
            Console.Clear();
            Console.WriteLine("--- Меню адмiнiстратора ---");
            Console.WriteLine("1. Перегляд всiх користувачiв");
            Console.WriteLine("2. Реєстрацiя нового користувача");
            Console.WriteLine("3. Видалення користувача");
            Console.WriteLine("4. Вийти з облiкового запису");

            Console.Write("Виберiть опцiю: ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    ShowAllUsers();
                    break;
                case "2":
                    RegisterNewUser();
                    break;
                case "3":
                    DeleteUser();
                    break;
                case "4":
                    LogAction("admin", "Вихід облікового запису з системи");
                    Console.WriteLine("\nВихiд з облiкового запису admin...");
                    Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
                    Console.ReadLine();
                    Console.Clear();
                    running = false; // Виходимо з циклу
                    break;
                default:
                    Console.WriteLine("Невiрний вибiр! Спробуйте ще раз.");
                    break;
            }
        }
    }

    static void UserMenu(string login) // Меню звичайного користувача
    {
        bool running = true;

        while (running)
        {
            Console.Clear();
            Console.WriteLine("--- Меню користувача ---");
            Console.WriteLine("1. Iнформацiя про облiковий запис");
            Console.WriteLine("2. Залишити повідомлення");
            Console.WriteLine("3. Вийти з облiкового запису");
            Console.Write("Виберiть опцiю: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    ShowUserInfo(login);
                    break;
                case "2":
                    LeaveMessage(login);
                    break;
                case "3":
                    LogAction(login, "Вихiд облiкового запису з системи");
                    Console.WriteLine($"\nВихiд з облiкового запису {login}");
                    Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
                    Console.ReadKey();
                    Console.Clear();
                    running = false;
                    break;
                default:
                    Console.WriteLine("Некоректний вибiр! Спробуйте ще раз.");
                    break;
            }
        }
    }

    

    static void HandleAdminKeyFile() // Перевірка наявності файлів ключів адміністратора і їх створення
    {
        string keyFilePath = "Administration/admin_keys.xml";
        if (!File.Exists(keyFilePath))
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                string publicKey = rsa.ToXmlString(false);
                string privateKey = rsa.ToXmlString(true);

                File.WriteAllText(keyFilePath, $"{publicKey}\n{privateKey}"); // Запис ключів у файл
            }
        }
    }

    static void EncryptUserData() // Шифрування і зберігання даних користувачів
    {
        string[] users = File.ReadAllLines(UserFile); // Зчитування користувачів з файлу
        StringBuilder encryptedData = new StringBuilder(); // Створення StringBuilder для зберігання зашифрованих даних

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            string privateKey = File.ReadAllText("Administration/admin_keys.xml").Split('\n')[1]; // Отримання приватного ключа з файлу
            rsa.FromXmlString(privateKey);

            foreach (var user in users)
            {
                var data = ParseUserData(user); // Парсинг даних користувача

                byte[] encryptedLogin = rsa.Encrypt(Encoding.UTF8.GetBytes(data.Login), false); // Шифрування логіна та пароля
                byte[] encryptedPassword = rsa.Encrypt(Encoding.UTF8.GetBytes(data.Password), false);

                string encryptedLoginStr = Convert.ToBase64String(encryptedLogin); // Перетворення зашифрованих даних в base64 для збереження в текстовому файлі
                string encryptedPasswordStr = Convert.ToBase64String(encryptedPassword);

                encryptedData.AppendLine($"login: {encryptedLoginStr}; password: {encryptedPasswordStr};");
            }
        }

        File.WriteAllText(EncryptedUserFile, encryptedData.ToString()); // Запис зашифрованих даних у файл
    }

    static void LogAction(string login, string action) // Функція для запису до журналу
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string logEntry = $"{timestamp}, {login}, {action}";
        File.AppendAllText(LogFile, logEntry + Environment.NewLine);
    }

    

    static void ShowAllUsers() // Функцiя для перегляду всiх користувачiв
    {
        Console.WriteLine("\n--- Список всiх користувачiв ---");

        if (File.Exists(UserFile))
        {
            string[] users = File.ReadAllLines(UserFile);
            foreach (var user in users)
            {
                var data = ParseUserData(user);
                Console.WriteLine($"Логiн: {data.Login}, Права доступу: {data.AccessRights}, Доступнi каталоги: {data.Directories}");
            }
        }
        else
        {
            Console.WriteLine("Файл користувачiв не знайдено!");
        }

        Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
        Console.ReadKey();
    }

    

    static void ShowUserInfo(string login) // Відображення інформації про користувача
    {
        string[] users = File.ReadAllLines(UserFile); // Читання користувачів з файлу
        string userLine = users.FirstOrDefault(u => u.Contains($"login: {login};"));

        if (userLine != null)
        {
            var userData = ParseUserData(userLine);

            Console.WriteLine($"\n--- Iнформацiя про облiковий запис {userData.Login} ---");
            Console.WriteLine("Доступнi каталоги: " + userData.Directories);
            Console.WriteLine("Права доступу: " + userData.AccessRights);
        }
        else
        {
            Console.WriteLine("Користувача не знайдено.");
        }

        Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
        Console.ReadKey();
    }

    static void LeaveMessage(string login) // Функція збереження повідомлення
    {
        string userMessagesDir = $"Messages/{login}_messages";

        if (!Directory.Exists(userMessagesDir)) // Створення папки для повідомлень, якщо вона не існує
        {
            Directory.CreateDirectory(userMessagesDir);
        }

        Console.WriteLine($"\n--- Створення повідомлення ---");
        Console.Write("Введіть назву: ");
        string messageName = Console.ReadLine();
        Console.Write("Введіть текст: ");
        string messageContent = Console.ReadLine();

        string messageFilePath = Path.Combine(userMessagesDir, $"{messageName}.txt");
        string encryptedFilePath = Path.Combine(userMessagesDir, $"{messageName}_encrypted.txt");
        string decryptedFilePath = Path.Combine(userMessagesDir, $"{messageName}_decrypted.txt");

        File.WriteAllText(messageFilePath, messageContent); // Запис тексту повідомлення у файл

        string userKeyFile = $"UsersKeys/{login}_keys.xml"; // Шифрування повідомлення
        if (!File.Exists(userKeyFile))
        {
            Console.WriteLine("Ключі для шифрування користувача не знайдено!");
            return;
        }

        string[] keys = File.ReadAllLines(userKeyFile);
        string publicKey = keys[0];
        string privateKey = keys[1];

        byte[] encryptedMessage;
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(publicKey);
            encryptedMessage = rsa.Encrypt(Encoding.UTF8.GetBytes(messageContent), false);
        }

        File.WriteAllBytes(encryptedFilePath, encryptedMessage); // Збереження зашифрованого повідомлення

        string decryptedMessage;
        using (var rsa = new RSACryptoServiceProvider(2048)) // Розшифрування повідомлення
        {
            rsa.FromXmlString(privateKey);
            byte[] decryptedBytes = rsa.Decrypt(encryptedMessage, false);
            decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
        }

        File.WriteAllText(decryptedFilePath, decryptedMessage); // Збереження розшифрованого повідомлення

        LogAction(login, "Створення повідомлення");
        Console.WriteLine("Повідомлення успішно збережено, зашифровано та розшифровано.");
        Console.WriteLine("\nНатисніть будь-яку клавішу...");
        Console.ReadKey();
    }

    static void RegisterNewUser() // Реєстрацiя та шифрування нового користувача
    {
        string[] existingUsers = File.ReadAllLines(UserFile);

        if (existingUsers.Length >= MaxUsers)
        {
            Console.WriteLine($"\nДосягнуто максимальну кiлькiсть користувачiв ({MaxUsers}).");
            Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("\n--- Реєстрацiя нового користувача ---");

        string newLogin;
        do
        {
            Console.Write("Введiть логiн: ");
            newLogin = Console.ReadLine();

            if (!IsLoginUnique(newLogin))
            {
                Console.WriteLine($"Логiн \"{newLogin}\" вже iснує! Спробуйте ще раз.");
            }
            else
            {
                break;
            }
        } while (true);

        Console.Write("Введiть пароль: ");
        string newPassword = Console.ReadLine();

        string accessRights;
        do
        {
            Console.Write("Введiть права доступу в такому форматі (E,R,W,A): ");
            accessRights = Console.ReadLine().ToUpper();

            if (!ValidateAccessRights(accessRights))
            {
                Console.WriteLine("Неправильний формат прав доступу! Спробуйте ще раз.");
            }
            else
            {
                break;
            }
        } while (true);

        string directories;
        do
        {
            Console.Write("Введiть доступ до каталогiв (A,B,C,D,E): ");
            directories = Console.ReadLine().ToUpper();

            if (!ValidateDirectories(directories))
            {
                Console.WriteLine("Неправильний формат доступу до каталогiв! Спробуйте ще раз.");
            }
            else
            {
                break;
            }
        } while (true);

        using (var rsa = new RSACryptoServiceProvider(2048)) // Генерацiя RSA-ключiв
        {
            string publicKey = rsa.ToXmlString(false);
            string privateKey = rsa.ToXmlString(true);

            byte[] encryptedLogin = rsa.Encrypt(Encoding.UTF8.GetBytes(newLogin), false); // Шифрування логiна та пароля
            byte[] encryptedPassword = rsa.Encrypt(Encoding.UTF8.GetBytes(newPassword), false);

            string keyFilePath = $"UsersKeys/{newLogin}_keys.xml"; // Збереження ключiв у XML-файл
            File.WriteAllText(keyFilePath, $"{publicKey}\n{privateKey}");

            using (StreamWriter writer = new StreamWriter(UserFile, true)) // Запис у файл користувачiв
            {
                writer.WriteLine($"login: {newLogin}; password: {newPassword}; accessRights: {accessRights}; directories: {directories};");
            }

            LogAction("Адміністратор", $"Створення облікового запису {newLogin}");
            EncryptUserData();

            Console.WriteLine($"Користувача {newLogin} успiшно зареєстровано!");
            Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
            Console.ReadKey();
        }
    }

    static bool ValidateDirectories(string directories) // Функцiя для перевiрки правильностi введених каталогiв
    {
        string[] validDirectories = new string[] { "A", "B", "C", "D", "E" };
        string[] inputDirectories = directories.Split(',');

        foreach (var dir in inputDirectories)
        {
            if (!validDirectories.Contains(dir))
            {
                return false;  // Якщо хоча б один каталог недопустимий, повертаємо false
            }
        }
        return true;  // Якщо всi каталоги правильнi
    }

    static bool ValidateAccessRights(string accessRights) // Функцiя для перевiрки валідації прав доступу
    {
        string[] validRights = new string[] { "E", "R", "W", "A", "D", "MAX" };

        string[] inputRights = accessRights.Split(',');

        foreach (var right in inputRights)
        {
            if (!validRights.Contains(right))
            {
                return false;  // Якщо хоча б одне право доступу недопустиме, повертаємо false
            }
        }
        return true;  // Якщо всi права доступу вказані вірно
    }

    static bool IsLoginUnique(string login) // Перевiрка унікальності логіну
    {
        string[] users = File.ReadAllLines(UserFile);

        foreach (var user in users)
        {
            var data = ParseUserData(user);

            if (data.Login == login)
            {
                return false;
            }
        }

        return true;  // Логiн унiкальний
    }

    static void DeleteUser() // Функцiя для видалення користувача
    {
        Console.WriteLine("\n--- Видалення користувача ---");
        Console.Write("Введiть логiн користувача для видалення: ");
        string loginToDelete = Console.ReadLine();

        if (loginToDelete.Equals("admin", StringComparison.OrdinalIgnoreCase)) // Перевiрка, чи це не admin
        {
            Console.WriteLine("Неможливо видалити адміністратора!");
            Console.ReadKey();
            return;
        }

        string[] users = File.ReadAllLines(UserFile);
        bool userFound = false;

        using (StreamWriter writer = new StreamWriter(UserFile)) // Формування нового списку користувачів після видалення користувача
        {
            foreach (var user in users)
            {
                var data = ParseUserData(user);

                if (data.Login == loginToDelete)
                {
                    userFound = true;
                    Console.WriteLine($"\nКористувач {loginToDelete} успiшно видалений.");
                    LogAction("Адміністратор", $"Видалення облікового запису {loginToDelete}");

                    string keyFilePath = $"UsersKeys/{loginToDelete}_keys.xml"; // Видаляємо файл ключів користувача
                    if (File.Exists(keyFilePath))
                    {
                        File.Delete(keyFilePath);
                    }

                    string messagesFolderPath = $"Messages/{loginToDelete}_messages"; // Видаляємо папку з повідомленнями користувача
                    if (Directory.Exists(messagesFolderPath))
                    {
                        Directory.Delete(messagesFolderPath, true); // true дозволяє видалити папку разом із файлами
                    }
                }
                else
                {
                    writer.WriteLine(user); // Перезаписуємо користувачів після видалення користувача
                }
            }
        }

        if (!userFound)
        {
            Console.WriteLine($"Користувача з логiном {loginToDelete} не знайдено.");
        }

        EncryptUserData(); // Оновлення зашифрованих даних
        Console.WriteLine("\nНатиснiть будь-яку клавiшу...");
        Console.ReadKey();
    }
}
