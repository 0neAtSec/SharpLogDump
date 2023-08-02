using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security;

namespace SharpLogDump
{
    class Program
    {
        static void Main(string[] args)
        {
            int days = 7;
            int logCounts = 4;
            string userName = "administrator";
            string domain = null;
            string remoteMachine = null;
            string remoteUser = null;
            string remotePassword = null;



            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-i" && i + 1 < args.Length)
                {
                    days = int.Parse(args[i + 1]);
                    i++;
                }
                else if (args[i] == "-c" && i + 1 < args.Length) 
                { 
                    logCounts = int.Parse(args[i + 1]);
                    i++;
                }
                else if (args[i] == "-f" && i + 1 < args.Length)
                {
                    userName = args[i + 1];
                    i++;
                }
                else if (args[i] == "-h" && i + 1 < args.Length)
                {
                    remoteMachine = args[i + 1];
                    i++;
                }
                else if (args[i] == "-d" && i + 1 < args.Length)
                {
                    domain = args[i + 1];
                    i++;
                }
                else if (args[i] == "-u" && i + 1 < args.Length)
                {
                    remoteUser = args[i + 1];
                    i++;
                }
                else if (args[i] == "-p" && i + 1 < args.Length)
                {
                    remotePassword = args[i + 1];
                    i++;
                }
                else if (args[i] == "-help")
                {
                    Console.WriteLine(@"
SharpLogDump.exe:
    Get the 4624 security logs of the local or remote server.
Usage:
    SharpLogDump.exe -help
    SharpLogDump.exe -i 10 -f zhangsan
    SharpLogDump.exe -h dc-ip -u administrator -p password -d domain -f zhangsan
    execute-assembly /path/to/SharpLogDump.exe");

                    Environment.Exit(0);
                }
            }

            Console.WriteLine(@"
SharpLogDump.exe:
    Get the 4624 security logs of the local or remote server.
");
            var logs = remoteMachine == null
                ? Get4624LogDetails(days, userName, logCounts)
                : Get4624LogDetailsRemote(remoteMachine, domain, remoteUser, remotePassword, days, userName, logCounts);

            foreach (var log in logs)
            {
                Console.WriteLine("Time Generated: " + log.Item1);
                Console.WriteLine("Target User SID: " + log.Item2);
                Console.WriteLine("Target User Name: " + log.Item3);
                Console.WriteLine("IP Address: " + log.Item4);
                Console.WriteLine("Target Domain Name: " + log.Item5);
                Console.WriteLine("Workstation Name: " + log.Item6);
                Console.WriteLine();
            }
        }
        public static Tuple<DateTime, string, string, string, string, string>[] Get4624LogDetails(int days = 7, string userName = "administrator", int logCounts = 4)
        {
            try
            {
                var log = new EventLog("Security");
                var startTime = DateTime.Now.AddDays(-days);
                var entries = log.Entries.Cast<EventLogEntry>()
                    .Where(e => e.InstanceId == 4624 && e.TimeGenerated >= startTime && GetTargetUserName(e).Equals(userName, StringComparison.OrdinalIgnoreCase))
                    .Reverse()
                    .Take(logCounts)
                    .Select(e => Tuple.Create(e.TimeGenerated, GetTargetUserSid(e), GetTargetUserName(e), GetIpAddress(e), GetTargetDomainName(e), GetWorkstationName(e)))
                    .ToArray();
                return entries;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
                return new Tuple<DateTime, string, string, string, string, string>[0];
            }
        }

        public static Tuple<DateTime, string, string, string, string, string>[] Get4624LogDetailsRemote(string machineName, string domain, string userName, string password, int days = 7, string targetUserName = "administrator", int logCounts = 4)
        {
            try
            {
                var securePassword = new SecureString();
                foreach (char c in password)
                {
                    securePassword.AppendChar(c);
                }
                securePassword.MakeReadOnly();
                var startTime = DateTime.Now.AddDays(-days);
                var query = new EventLogQuery("Security", PathType.LogName) { ReverseDirection = true };
                if (!string.IsNullOrEmpty(machineName))
                {
                    query.Session = new EventLogSession(machineName, domain, userName, securePassword, SessionAuthentication.Default);
                }

                var reader = new EventLogReader(query);
                var events = new EventRecord[logCounts];
                EventRecord eventInstance;
                var count = 0;
                while ((eventInstance = reader.ReadEvent()) != null && count < logCounts)
                {
                    if (eventInstance.Id == 4624 && eventInstance.TimeCreated >= startTime && eventInstance.Properties[5].Value.ToString().Equals(targetUserName, StringComparison.OrdinalIgnoreCase))
                    {
                        events[count++] = eventInstance;
                    }
                }

                var entries = events
                    .Where(e => e != null)
                    .Select(e => Tuple.Create(
                        e.TimeCreated.Value,
                        e.Properties[4].Value.ToString(),
                        e.Properties[5].Value.ToString(),
                        e.Properties[18].Value.ToString(),
                        e.Properties[6].Value.ToString(),
                        e.Properties[11].Value.ToString()))
                    .ToArray();

                return entries;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
                return new Tuple<DateTime, string, string, string, string, string>[0];
            }
        }

        private static string GetTargetUserSid(EventLogEntry entry)
        {
            var targetUserSid = entry.ReplacementStrings[4];
            return targetUserSid;
        }

        private static string GetTargetUserName(EventLogEntry entry)
        {
            var targetUserName = entry.ReplacementStrings[5];
            return targetUserName;
        }

        private static string GetIpAddress(EventLogEntry entry)
        {
            var ipAddress = entry.ReplacementStrings[18];
            return ipAddress;
        }

        private static string GetTargetDomainName(EventLogEntry entry)
        {
            var targetDomainName = entry.ReplacementStrings[6];
            return targetDomainName;
        }

        private static string GetWorkstationName(EventLogEntry entry)
        {
            var workstationName = entry.ReplacementStrings[11];
            return workstationName;
        }

    }


}

