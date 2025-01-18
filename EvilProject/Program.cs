using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using suo_exploit_test.Helpers.ModifiedVulnerableBinaryFormatters;
using OpenMcdf;
using System.Runtime.InteropServices;
using System.Threading;

namespace EvilProject
{
    internal class Program
    {
        public static Action[] GetModules()
        {
            var methods = typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public);
            var moduleActions = methods.Select(method =>
            {
                return new Action(() =>
                {
                    var parameters = method.GetParameters();
                    var parameterValues = new object[parameters.Length];
                    for (int i = 0; i < parameters.Length; i++)
                    {
                        parameterValues[i] = GetDefaultParameterValue(parameters[i].ParameterType);
                    }

                    method.Invoke(null, parameterValues);
                });
            }).ToArray();

            return moduleActions;
        }

        private static object GetDefaultParameterValue(Type type)
        {
            if (type == typeof(int)) return 0;
            if (type == typeof(string)) return string.Empty;
            if (type == typeof(bool)) return false;
            return null;
        }

        public static string SunsetASCII = "⠀⠀⠀⠀⠀⠀⢀⣤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⢤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀\r\n⠀⠀⠀⠀⢀⡼⠋⠀⣀⠄⡂⠍⣀⣒⣒⠂⠀⠬⠤⠤⠬⠍⠉⠝⠲⣄⡀⠀⠀ \r\n⠀⠀⠀⢀⡾⠁⠀⠊⢔⠕⠈⣀⣀⡀⠈⠆⠀⠀⠀⡍⠁⠀⠁⢂⠀⠈⣷⠀⠀\r\n⠀⠀⣠⣾⠥⠀⠀⣠⢠⣞⣿⣿⣿⣉⠳⣄⠀⠀⣀⣤⣶⣶⣶⡄⠀⠀⣘⢦⡀\r\n⢀⡞⡍⣠⠞⢋⡛⠶⠤⣤⠴⠚⠀⠈⠙⠁⠀⠀⢹⡏⠁⠀⣀⣠⠤⢤⡕⠱⣷\r\n⠘⡇⠇⣯⠤⢾⡙⠲⢤⣀⡀projectroll⠈⠉⣸⡄⠠⣠⡿\r\n⠀⠹⣜⡪⠀⠈⢷⣦⣬⣏⠉⠛⠲⣮⣧⣁⣀⣀⠶⠞⢁⣀⣨⢶⢿⣧⠉⡼⠁\r\n⠀⠀⠈⢷⡀⠀⠀⠳⣌⡟⠻⠷⣶⣧⣀⣀⣹⣉⣉⣿⣉⣉⣇⣼⣾⣿⠀⡇⠀\r\n⠀⠀⠀⠈⢳⡄⠀⠀⠘⠳⣄⡀⡼⠈⠉⠛⡿⠿⠿⡿⠿⣿⢿⣿⣿⡇⠀⡇⠀\r\n⠀⠀⠀⠀⠀⠙⢦⣕⠠⣒⠌⡙⠓⠶⠤⣤⣧⣀⣸⣇⣴⣧⠾⠾⠋⠀⠀⡇⠀\r\n⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⣭⣒⠩⠖⢠⣤⠄⠀⠀⠀⠀⠀⠠⠔⠁⡰⠀⣧⠀\r\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠲⢤⣀⣀⠉⠉⠀⠀⠀⠀⠀⠁⠀⣠⠏⠀\r\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠒⠲⠶⠤⠴⠒⠚⠁⠀⠀";
        public static (int option, string[] arguments) ParseInput(string input, int maxModules)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException("Input cannot be empty.");

            var parts = input.Split(',')
                             .Select(p => p.Trim())
                             .ToArray();

            if (parts.Length == 0)
                throw new ArgumentException("No valid input provided.");

            if (!int.TryParse(parts[0], out int option) || option < 1 || option > maxModules)
                throw new ArgumentException("Invalid module option.");

            string[] arguments = parts.Skip(1).ToArray();

            return (option, arguments);
        }
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            EConsole.Write($"[[DARKGRAY]]{SunsetASCII}[[RESET]]", true);
            Console.Title = "Projectroll";

            if (args.Length > 0)
            {
                if (args[0] == "--help")
                {
                    EConsole.Write($"\n[[GREEN]]============================\n[[CYAN]] Modules using:\n[[RESET]]{Process.GetCurrentProcess().ProcessName} --module=<MODULE_NUMBER> <ARGUMENTS>\nE.g.: {Process.GetCurrentProcess().ProcessName} --module=2 path=C:\\SomeLocalInDisk command=\"calc\" \n\n[[DARKGRAY]] --modules - Shows a list of all available modules\n --help - Shows this help message\n\nPro Tip: You can also use the menu version which is easier to use by just opening the executable.\n[[GREEN]]============================", true);
                    return;
                }
                if (args[0] == "--modules")
                {
                    Console.WriteLine("Available modules:\n");
                    for (int i = 0; i < typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public).Length; i++)
                    {
                        var methodInfo = typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public)[i];
                        var paramDescriptions = methodInfo.GetParameters()
                        .Select(param => $"[[BLUE]]{param.ParameterType.Name}[[RESET]]: [[CYAN]]{param.Name}").ToArray();
                        string paramList = paramDescriptions.Length > 0 ? string.Join(", ", paramDescriptions) : "No parameters";

                        EConsole.Write($"  {i + 1}. [[YELLOW]]{methodInfo.Name}[[RESET]]([[yellow]]{paramList}[[RESET]])", true);
                    }
                    return;
                }
                try
                {
                    string moduleArg = args.FirstOrDefault(arg => arg.StartsWith("--module="));

                    if (moduleArg == null)
                        throw new ArgumentException("No --module argument provided.");

                    string moduleValue = moduleArg.Replace("--module=", "").Trim();
                    if (!int.TryParse(moduleValue, out int moduleIndex) || moduleIndex < 1)
                        throw new ArgumentException("Invalid module index.");

                    var methods = typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public);
                    if (moduleIndex > methods.Length)
                        throw new ArgumentException("Module index out of range.");

                    var method = methods[moduleIndex - 1];
                    var parameters = method.GetParameters();

                    var parsedArguments = new object[parameters.Length];
                    foreach (var param in parameters)
                    {
                        string argument = args.FirstOrDefault(arg => arg.StartsWith($"{param.Name}="));
                        if (argument == null)
                            throw new ArgumentException($"Missing argument for parameter: {param.Name}");

                        string value = argument.Split(new[] { '=' }, 2, StringSplitOptions.None)[1];
                        parsedArguments[Array.IndexOf(parameters, param)] = Convert.ChangeType(value, param.ParameterType);
                    }

                    method.Invoke(null, parsedArguments);
                    return;
                }
                catch (Exception ex)
                {
                    EConsole.ELog($"{ex.Message} --> {ex.StackTrace}", 3);
                    return;
                }
            }

            EConsole.ELog($"Welcome, {System.Environment.UserName}!", 0);

            Console.WriteLine("\n Select a module: ");
            var modules = GetModules();

            for (int i = 0; i < typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public).Length; i++)
            {
                var methodInfo = typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public)[i];
                var paramDescriptions = methodInfo.GetParameters()
                .Select(param => $"[[BLUE]]{param.ParameterType.Name}[[RESET]]: [[CYAN]]{param.Name}").ToArray();
                string paramList = paramDescriptions.Length > 0 ? string.Join(", ", paramDescriptions) : "No parameters";

                EConsole.Write($"  {i + 1}. [[YELLOW]]{methodInfo.Name}[[RESET]]([[yellow]]{paramList}[[RESET]])", true);
            }

            try
            {
                var methods = typeof(Modules).GetMethods(BindingFlags.Static | BindingFlags.Public);

                EConsole.Write("[[CYAN]] > ", false);
                string moduleNumber = Console.ReadLine();

                if (moduleNumber.Trim().ToLower() == "clear")
                {
                    Console.Clear();
                    Main(new string[] { });
                    return;
                }
                if (int.Parse(moduleNumber) < 1 || int.Parse(moduleNumber) > methods.Length)
                {
                    EConsole.ELog("Invalid selection!", 3);
                    return;
                }

                var selectedMethod = methods[int.Parse(moduleNumber) - 1];
                var parameters = selectedMethod.GetParameters();

                if (parameters.Length == 0)
                {
                    selectedMethod.Invoke(null, null);
                    return;
                }

                var arguments = new List<object>();

                foreach (var parameter in parameters)
                {
                    EConsole.Write($"[[CYAN]] > [[RESET]]Insert parameter '{parameter.Name}' value ({parameter.ParameterType}): ", false);
                    string input = Console.ReadLine();
                    var parsedArgument = Convert.ChangeType(input, parameter.ParameterType);
                    arguments.Add(parsedArgument);
                }

                selectedMethod.Invoke(null, arguments.ToArray());
            }
            catch (Exception ex)
            {
                EConsole.ELog("Error occurred while trying to invoke function: " + ex.Message, 3);
            }

        }
    }
}
