using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EvilProject
{
    internal class EConsole
    {
        public static void Write(string input, bool NewLine)
        {
            var ColorMap = new Dictionary<string, ConsoleColor>(StringComparer.OrdinalIgnoreCase)
    {
        { "BLACK", ConsoleColor.Black },
        { "DARKBLUE", ConsoleColor.DarkBlue },
        { "DARKGREEN", ConsoleColor.DarkGreen },
        { "DARKCYAN", ConsoleColor.DarkCyan },
        { "DARKRED", ConsoleColor.DarkRed },
        { "DARKMAGENTA", ConsoleColor.DarkMagenta },
        { "DARKYELLOW", ConsoleColor.DarkYellow },
        { "GRAY", ConsoleColor.Gray },
        { "DARKGRAY", ConsoleColor.DarkGray },
        { "BLUE", ConsoleColor.Blue },
        { "GREEN", ConsoleColor.Green },
        { "CYAN", ConsoleColor.Cyan },
        { "RED", ConsoleColor.Red },
        { "MAGENTA", ConsoleColor.Magenta },
        { "YELLOW", ConsoleColor.Yellow },
        { "WHITE", ConsoleColor.White },
        { "RESET", Console.ForegroundColor }
    };

            ConsoleColor originalForeground = Console.ForegroundColor;
            ConsoleColor originalBackground = Console.BackgroundColor;

            string[] tokens = input.Split(new string[] { "[[" }, StringSplitOptions.None);

            foreach (string token in tokens)
            {
                if (token.Contains("]]"))
                {
                    string[] parts = token.Split(new string[] { "]]" }, StringSplitOptions.None);
                    string colorKey = parts[0].ToUpper();
                    string text = parts.Length > 1 ? parts[1] : "";

                    if (ColorMap.TryGetValue(colorKey, out ConsoleColor consoleColor))
                    {
                        Console.ForegroundColor = consoleColor;
                    }

                    Console.Write(text);
                    Console.ForegroundColor = originalForeground;
                }
                else
                {
                    Console.Write(token);
                }
            }

            if (NewLine) { Console.WriteLine(); }
            Console.ForegroundColor = originalForeground;
            Console.BackgroundColor = originalBackground;
        }

        public static void ELog(string message, int type)
        {
            ConsoleColor originalColor = Console.ForegroundColor;

            switch (type)
            {
                case 1:
                    EConsole.Write($"[[GREEN]] [{DateTime.Now.TimeOfDay.ToString().Split('.')[0]} - SUCCESS]: [[GRAY]]{message}", true);
                    break;

                case 2:
                    EConsole.Write($"[[YELLOW]] [{DateTime.Now.TimeOfDay.ToString().Split('.')[0]} - WARNING]: [[GRAY]]{message}", true);
                    break;

                case 3:
                    EConsole.Write($"[[RED]] [{DateTime.Now.TimeOfDay.ToString().Split('.')[0]} - ERROR]: [[GRAY]]{message}", true);
                    break;

                default:
                    EConsole.Write($"[[DARKGRAY]] [{DateTime.Now.TimeOfDay.ToString().Split('.')[0]} - INFO]: [[GRAY]]{message}", true);
                    break;
            }

            Console.ForegroundColor = originalColor;
        }

    }
}
