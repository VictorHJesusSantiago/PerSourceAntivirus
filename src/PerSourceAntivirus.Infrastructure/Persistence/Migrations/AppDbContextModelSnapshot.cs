
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using PerSourceAntivirus.Infrastructure.Persistence;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    [DbContext(typeof(AppDbContext))]
    partial class AppDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "9.0.0");

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ActiveLearningSample", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("FeaturesJson")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsMalicious")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("RecordedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Sha256")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("RecordedAtUtc");

                    b.ToTable("ActiveLearningSamples", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AdsStreamInfo", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("StreamName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<long>("StreamSize")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId");

                    b.ToTable("AdsStreamInfos", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AlertTriage", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<Guid>("AlertId")
                        .HasColumnType("TEXT");

                    b.Property<string>("AlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("AutoSeverityScore")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<Guid?>("IncidentId")
                        .HasColumnType("TEXT");

                    b.Property<string>("Notes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("TriagedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("TriagedBy")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("IncidentId");

                    b.HasIndex("Status");

                    b.ToTable("AlertTriages", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AmsiBypassAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AffectedFunction")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("BypassMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Details")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("AmsiBypassAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AmsiScanEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("AmsiResult")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ContentName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ScannedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("ScannedAtUtc");

                    b.ToTable("AmsiScanEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ApiCallSequenceAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("ApiSequence")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("PatternName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("ApiCallSequenceAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AppWhitelistEntry", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Action")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("EntryType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Value")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IsEnabled");

                    b.HasIndex("EntryType", "Value");

                    b.ToTable("AppWhitelistEntries", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ArchiveEntryResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ArchiveScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<double>("Entropy")
                        .HasColumnType("REAL");

                    b.Property<string>("EntryPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<long>("EntrySize")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ScanDepth")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("ArchiveScannedFileId");

                    b.ToTable("ArchiveEntryResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ArpSpoofingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AttackerMac")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("DuplicateCount")
                        .HasColumnType("INTEGER");

                    b.Property<string>("LegitimateKnownMac")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SpoofedMac")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("VictimIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ArpSpoofingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AtomBombingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("AtomContentEntropy")
                        .HasColumnType("REAL");

                    b.Property<int>("AtomContentLength")
                        .HasColumnType("INTEGER");

                    b.Property<ushort>("AtomId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspiciousAtomContent")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("AtomBombingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AuditLogChainEntry", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("EntryHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("EventDescription")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("PreviousHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("RecordedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<long>("SequenceNumber")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("SequenceNumber")
                        .IsUnique();

                    b.ToTable("AuditLogChainEntries", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AutostartEntry", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AuditedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Classification")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Command")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("EntryName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsKnown")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Location")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Publisher")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AuditedAtUtc");

                    b.HasIndex("IsSuspicious");

                    b.ToTable("AutostartEntries", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.BeaconingAnalysis", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("AverageIntervalSeconds")
                        .HasColumnType("REAL");

                    b.Property<int>("BeaconingScore")
                        .HasColumnType("INTEGER");

                    b.Property<string>("DestinationIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("DestinationPort")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsOutsideBusinessHours")
                        .HasColumnType("INTEGER");

                    b.Property<double>("JitterVariance")
                        .HasColumnType("REAL");

                    b.Property<double>("PayloadSizeVariance")
                        .HasColumnType("REAL");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("SampleCount")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("BeaconingScore");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("BeaconingAnalyses", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.BrowserCredentialAccessAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("AccessingPid")
                        .HasColumnType("INTEGER");

                    b.Property<string>("AccessingProcess")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Browser")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CredentialFilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("BrowserCredentialAccessAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.BrowserExtensionFinding", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AuditedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Browser")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtensionId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtensionName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Permissions")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RiskReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Version")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("AuditedAtUtc");

                    b.HasIndex("IsSuspicious");

                    b.ToTable("BrowserExtensionFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CertificateTrustAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SubjectName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Thumbprint")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("CertificateTrustAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CertificateTrustEntry", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AddedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Note")
                        .HasColumnType("TEXT");

                    b.Property<string>("SubjectName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Thumbprint")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TrustLevel")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("Thumbprint")
                        .IsUnique();

                    b.ToTable("CertificateTrustEntries", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CfgViolationAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Details")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("ExceptionCode")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ViolationAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("CfgViolationAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ClipboardHijackAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AddressType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("OriginalContent")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspectedWalletAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ClipboardHijackAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ComHijackAlert", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("AlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ClsidOrPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<string>("LegitimateSystemPath")
                        .HasColumnType("TEXT");

                    b.Property<string>("Severity")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspiciousPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ComHijackAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CryptojackingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("CpuPercent")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RemoteAddress")
                        .HasColumnType("TEXT");

                    b.Property<int>("RemotePort")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("CryptojackingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CustomIoc", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("IocType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsActive")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime?>("LastMatchedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Tags")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Value")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IsActive");

                    b.HasIndex("IocType", "Value");

                    b.ToTable("CustomIocs", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.CustomSignatureMatch", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FileHashSha256")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("MatchType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SignatureName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("FileHashSha256");

                    b.ToTable("CustomSignatureMatches", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.DgaAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("ConsonantVowelRatio")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<double>("EntropyScore")
                        .HasColumnType("REAL");

                    b.Property<string>("Hostname")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsDga")
                        .HasColumnType("INTEGER");

                    b.Property<int>("NxdomainStreak")
                        .HasColumnType("INTEGER");

                    b.Property<double>("Probability")
                        .HasColumnType("REAL");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("IsDga");

                    b.ToTable("DgaAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.DirectSyscallAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("ContainingModulePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("InstructionType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsInSystemModule")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<ulong>("SyscallInstructionAddress")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("DirectSyscallAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.DllHijackAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DllName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExpectedSystemDllPath")
                        .HasColumnType("TEXT");

                    b.Property<string>("HijackType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("LoadedDllPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("DllHijackAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.DnsQueryEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CapturedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("QueryName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("QueryType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SourceAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspicionReason")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("DnsQueryEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.DnsTunnelingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("AverageLabelEntropy")
                        .HasColumnType("REAL");

                    b.Property<double>("AverageQueryLength")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("QueriesInWindow")
                        .HasColumnType("INTEGER");

                    b.Property<string>("QueryDomain")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SourceAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("DnsTunnelingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.EmailScanResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("AttachmentCount")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasSpoofedSender")
                        .HasColumnType("INTEGER");

                    b.Property<string>("PhishingIndicators")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("PhishingLinkCount")
                        .HasColumnType("INTEGER");

                    b.Property<int>("RiskScore")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("ScannedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<int>("SuspiciousAttachmentCount")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousAttachmentNames")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId");

                    b.ToTable("EmailScanResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.EmulationResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("ApiCallsIntercepted")
                        .HasColumnType("INTEGER");

                    b.Property<string>("DetectedPatterns")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("EmulatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("InstructionCount")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("EmulatedAtUtc");

                    b.ToTable("EmulationResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ExploitFinding", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<long>("BaseAddress")
                        .HasColumnType("INTEGER");

                    b.Property<float>("ConfidenceScore")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectedPatterns")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ExploitFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.FileActivityEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("FileName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<long>("FileSize")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("OccurredAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Operation")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Sha256Hash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IsSuspicious");

                    b.HasIndex("OccurredAtUtc");

                    b.HasIndex("ProcessId");

                    b.ToTable("FileActivityEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.FileMetadataAnalysisResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Anomalies")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Author")
                        .HasColumnType("TEXT");

                    b.Property<string>("Creator")
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("DocumentCreatedUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("DocumentModifiedUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasEmbeddedFiles")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasJavaScript")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsPolyglot")
                        .HasColumnType("INTEGER");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId")
                        .IsUnique();

                    b.ToTable("FileMetadataResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.FilelessAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Detail")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TechniqueType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("FilelessAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.FirmwareVariableSnapshot", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("BaselineValueHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ChangeDescription")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CurrentValueHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("SnapshotAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("VariableName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("VariableNamespace")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IsSuspicious");

                    b.HasIndex("SnapshotAtUtc");

                    b.ToTable("FirmwareVariableSnapshots", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.GeoIpBlockAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CountryCode")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Direction")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RemoteAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("GeoIpBlockAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HashReputationResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CheckedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsMalicious")
                        .HasColumnType("INTEGER");

                    b.Property<int>("PositiveDetections")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ReportUrl")
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("Source")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("TotalEngines")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId")
                        .IsUnique();

                    b.ToTable("HashReputationResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HeapSprayAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("AverageRegionEntropy")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("SuspiciousRegionCount")
                        .HasColumnType("INTEGER");

                    b.Property<long>("TotalPrivateCommittedBytes")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("ProcessId");

                    b.ToTable("HeapSprayAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HeavensGateAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<ulong>("DetectedPatternAddress")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsWow64Process")
                        .HasColumnType("INTEGER");

                    b.Property<string>("PatternBytes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("PatternType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("HeavensGateAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HoneypotFile", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DecoyType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FileName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("LastCheckedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("TouchedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasTouched")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.ToTable("HoneypotFiles", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HostIsolationEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Action")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("TriggeredAtUtc")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("TriggeredAtUtc");

                    b.ToTable("HostIsolationEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HypervisorDetectionResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CpuidLeaf")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethods")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("HypervisorType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsVirtualMachine")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("IsVirtualMachine");

                    b.ToTable("HypervisorDetectionResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.Incident", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("AlertCount")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("ResolvedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Title")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("Severity");

                    b.HasIndex("Status");

                    b.ToTable("Incidents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.KernelPatchGuardAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("BypassMethodType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Details")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TargetFunction")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("KernelPatchGuardAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.KeyloggerDetectionAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ModulePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousDetail")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("KeyloggerDetectionAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.LlmnrPoisoningAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Protocol")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("QuerierIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("QueryName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ResponderIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ResponderMac")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SpoofedIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("LlmnrPoisoningAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.LolBinAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AlertedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Arguments")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("LolbinName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("MitreTechnique")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AlertedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("LolBinAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.MbrSnapshot", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("DriveIndex")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsBaseline")
                        .HasColumnType("INTEGER");

                    b.Property<int>("SectorSize")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Sha256Hash")
                        .IsRequired()
                        .HasMaxLength(64)
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("TakenAtUtc")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DriveIndex", "IsBaseline");

                    b.ToTable("MbrSnapshots", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.MbrWriteAttemptAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("DriveNumber")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<long>("Sector")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("MbrWriteAttemptAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.MemoryDumpResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DumpFilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtractedIps")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtractedStrings")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtractedUrls")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousImports")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("ProcessId");

                    b.ToTable("MemoryDumpResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.MicrophoneAccessEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DevicePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("MicrophoneAccessEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.MitreAttackMapping", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("MitreUrl")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Tactic")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TechniqueId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TechniqueName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("AlertType")
                        .IsUnique();

                    b.ToTable("MitreAttackMappings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ModuleStompingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("InMemoryHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ModuleName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ModulePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("OnDiskHash")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<long>("TextSectionSize")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ModuleStompingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NetworkBehaviorAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AnomalyReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("UnexpectedIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("UnexpectedPort")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("NetworkBehaviorAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NetworkBehaviorProfile", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("BaselineIps")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("BaselinePorts")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("FirstSeenAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("LastUpdatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ObservationCount")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("LastUpdatedAtUtc");

                    b.HasIndex("ProcessName")
                        .IsUnique();

                    b.ToTable("NetworkBehaviorProfiles", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NetworkConnectionEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("BlocklistReason")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CapturedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DestinationAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("DestinationPort")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsBlocklisted")
                        .HasColumnType("INTEGER");

                    b.Property<int>("PacketLength")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Protocol")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SourceAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("SourcePort")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.ToTable("NetworkConnectionEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NetworkIntrusionAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("DestinationIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("DestinationPort")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("MatchedPattern")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("PayloadLength")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Protocol")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SignatureName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SourceIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("SourcePort")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("NetworkIntrusionAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NotificationRecord", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("AcknowledgedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Message")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("NotificationType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<Guid?>("RelatedEntityId")
                        .HasColumnType("TEXT");

                    b.Property<string>("RelatedEntityType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Title")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("Status");

                    b.ToTable("NotificationRecords", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.NtdllUnhookingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("MappedNtdllCount")
                        .HasColumnType("INTEGER");

                    b.Property<string>("MappedPaths")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("TargetProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TargetProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("NtdllUnhookingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.OfficeMacroAnalysisResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasAutoExec")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasMacros")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasNetworkAccess")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasObfuscation")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasProcessExecution")
                        .HasColumnType("INTEGER");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspiciousPatterns")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId")
                        .IsUnique();

                    b.ToTable("OfficeMacroResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.OpenPortInfo", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsKnownRisk")
                        .HasColumnType("INTEGER");

                    b.Property<int>("LocalPort")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Protocol")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RemoteAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("RemotePort")
                        .HasColumnType("INTEGER");

                    b.Property<string>("RiskDescription")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ScannedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("State")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("LocalPort");

                    b.HasIndex("ScannedAtUtc");

                    b.ToTable("OpenPortInfos", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ParentChildAnomalyAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AnomalyReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ChildCommandLine")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ChildProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ChildProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ParentProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ParentProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("ParentChildAnomalyAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PdfScanResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasEmbeddedFiles")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasJavaScript")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasLaunchAction")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasObjStm")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasOpenAction")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasRichMedia")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasXfa")
                        .HasColumnType("INTEGER");

                    b.Property<string>("MaliciousObjectTypes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("RiskScore")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("ScannedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId");

                    b.ToTable("PdfScanResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeAnalysisResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Anomalies")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("Is64Bit")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsDll")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsDotNet")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsSigned")
                        .HasColumnType("INTEGER");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspiciousImports")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId")
                        .IsUnique();

                    b.ToTable("PeAnalysisResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeMlPrediction", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Classification")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FeaturesJson")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<float>("MaliciousProbability")
                        .HasColumnType("REAL");

                    b.Property<string>("ModelVersion")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("PredictedAtUtc")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("Classification");

                    b.ToTable("PeMlPredictions", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeSection", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("Entropy")
                        .HasColumnType("REAL");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<Guid>("PeAnalysisResultId")
                        .HasColumnType("TEXT");

                    b.Property<uint>("SizeOfRawData")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("PeAnalysisResultId");

                    b.ToTable("PeSections", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PlaybookExecutionLog", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("ActionsExecuted")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("AlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ErrorMessage")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ExecutedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .HasColumnType("TEXT");

                    b.Property<int?>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<Guid>("RuleId")
                        .HasColumnType("TEXT");

                    b.Property<string>("RuleName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("Success")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("ExecutedAtUtc");

                    b.ToTable("PlaybookExecutionLogs", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PortScanAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("ConnectionCount")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SourceIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TargetPorts")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<double>("TimeWindowMs")
                        .HasColumnType("REAL");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("PortScanAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessCommandLineAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CommandLine")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<int>("SuspicionScore")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Triggers")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("ProcessCommandLineAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessCreationEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CommandLine")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FileName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("IntegrityLevel")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ParentImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ParentProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Sha256Hash")
                        .IsRequired()
                        .HasMaxLength(64)
                        .HasColumnType("TEXT");

                    b.Property<string>("UserName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("IsSuspicious");

                    b.HasIndex("ProcessId");

                    b.ToTable("ProcessCreationEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessDoppelgangingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("ImageExistsOnDisk")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ReportedImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ProcessDoppelgangingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CommandLine")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ParentProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ParentProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SuspicionReason")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("ProcessEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessFirewallRule", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Action")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AddedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("ProcessPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Reason")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ProcessPath");

                    b.ToTable("ProcessFirewallRules", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessGhostingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("ImageFileAccessible")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("ImageFileExistsOnDisk")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ReportedImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ProcessGhostingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ProcessHollowingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectedSequence")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("InjectorProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("InjectorProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<int>("StepsDetected")
                        .HasColumnType("INTEGER");

                    b.Property<int>("TargetProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TargetProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("ProcessHollowingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PuaAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Category")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionDetails")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ImagePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("Category");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("PuaAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.RansomwareAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Detail")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("EventType")
                        .HasColumnType("INTEGER");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("RansomwareAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ReflectiveDllInjectionAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasPeHeader")
                        .HasColumnType("INTEGER");

                    b.Property<uint>("MemoryProtection")
                        .HasColumnType("INTEGER");

                    b.Property<double>("RegionEntropy")
                        .HasColumnType("REAL");

                    b.Property<long>("RegionSize")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<ulong>("SuspiciousBaseAddress")
                        .HasColumnType("INTEGER");

                    b.Property<int>("TargetProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TargetProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("TargetProcessId");

                    b.ToTable("ReflectiveDllInjectionAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.RegistryActivityEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("KeyPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("NewData")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("OccurredAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("OldData")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Operation")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ValueName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IsSuspicious");

                    b.HasIndex("OccurredAtUtc");

                    b.HasIndex("ProcessId");

                    b.ToTable("RegistryActivityEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.RemoteAgentEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("DeviceProduct")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("DeviceVendor")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExtensionsJson")
                        .HasColumnType("TEXT");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ReceivedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SignatureId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SourceHost")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ReceivedAtUtc");

                    b.ToTable("RemoteAgentEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ResponsePlaybookRule", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Actions")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<int>("MinSeverity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TriggerAlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("ResponsePlaybookRules", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.RootkitFinding", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("FindingType")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .HasColumnType("TEXT");

                    b.Property<string>("Severity")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("RootkitFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SafeFolderViolationAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AttemptedOperation")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ProtectedPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("WasBlocked");

                    b.ToTable("SafeFolderViolationAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SampleSubmissionRecord", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("ErrorMessage")
                        .HasColumnType("TEXT");

                    b.Property<string>("OriginalFilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("PackagedArchivePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("Submitted")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SubmittedToUrl")
                        .HasColumnType("TEXT");

                    b.Property<bool>("Success")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.ToTable("SampleSubmissionRecords", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScanProfile", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("ExcludePaths")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FileExtensions")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("IncludePaths")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsDefault")
                        .HasColumnType("INTEGER");

                    b.Property<long>("MaxFileSizeBytes")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ProfileType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.HasIndex("IsDefault");

                    b.ToTable("ScanProfiles", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScannedFile", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("Entropy")
                        .HasColumnType("REAL");

                    b.Property<string>("FileName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsQuarantined")
                        .HasColumnType("INTEGER");

                    b.Property<string>("QuarantinePath")
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("QuarantinedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ScannedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Sha256Hash")
                        .IsRequired()
                        .HasMaxLength(64)
                        .HasColumnType("TEXT");

                    b.Property<long>("SizeBytes")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ThreatStatus")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.ToTable("ScannedFiles", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScheduledScan", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("IntervalMinutes")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime?>("LastRunAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Path")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("ScheduledScans", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScreenCaptureAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CaptureMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("TargetWindowTitle")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ScreenCaptureAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScreenLockerAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasFullscreenWindow")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasKeyboardHook")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasMouseHook")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasTerminated")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("ScreenLockerAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScriptAnalysisResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasFileSystemAccess")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasNetworkAccess")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasObfuscation")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("HasProcessExecution")
                        .HasColumnType("INTEGER");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<int>("ScriptType")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousPatterns")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId")
                        .IsUnique();

                    b.ToTable("ScriptAnalysisResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScriptSandboxResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<int>("AmsiScore")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("AnalyzedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("BehavioralFindings")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ScriptHash")
                        .IsRequired()
                        .HasMaxLength(64)
                        .HasColumnType("TEXT");

                    b.Property<string>("ScriptPreview")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ScriptType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Verdict")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasSandboxed")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AnalyzedAtUtc");

                    b.HasIndex("Verdict");

                    b.ToTable("ScriptSandboxResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SecureBootStatusSnapshot", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Anomalies")
                        .HasColumnType("TEXT");

                    b.Property<string>("BootloaderHashSha256")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("BootloaderPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("BootloaderSigned")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("BootloaderTrusted")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("CheckedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("SecureBootEnabled")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("CheckedAtUtc");

                    b.ToTable("SecureBootStatusSnapshots", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SecurityPostureIssue", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("Category")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CheckName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CheckedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("CurrentValue")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ExpectedValue")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("IssueDescription")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("CheckedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("SecurityPostureIssues", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SensitiveDataFinding", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("DataType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("FoundAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("LineNumber")
                        .HasColumnType("INTEGER");

                    b.Property<string>("MatchSnippet")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DataType");

                    b.HasIndex("FoundAtUtc");

                    b.ToTable("SensitiveDataFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ServiceAuditFinding", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AuditedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("BinaryPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FindingType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSystemService")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsUnquotedPath")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsWritablePath")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ServiceDisplayName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ServiceName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AuditedAtUtc");

                    b.ToTable("ServiceAuditFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SmbLateralMovementAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("PipeName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ShareName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SourceIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TargetIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("SmbLateralMovementAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.StackPivotAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<ulong>("RspValue")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<ulong>("StackBase")
                        .HasColumnType("INTEGER");

                    b.Property<ulong>("StackLimit")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ThreadId")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("StackPivotAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SteganographyAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("ChannelEntropy")
                        .HasColumnType("REAL");

                    b.Property<double>("ChiSquareScore")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<double>("HistogramAnomalyScore")
                        .HasColumnType("REAL");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspicionReasons")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("IsSuspicious");

                    b.ToTable("SteganographyAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.StixFeedSource", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("FeedType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("IocCount")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<string>("LastStatus")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("LastUpdatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Url")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("StixFeedSources", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.StixIoc", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<double>("Confidence")
                        .HasColumnType("REAL");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<Guid>("FeedSourceId")
                        .HasColumnType("TEXT");

                    b.Property<string>("IocType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Labels")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ThreatActors")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Value")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("FeedSourceId");

                    b.HasIndex("IocType", "Value");

                    b.ToTable("StixIocs", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.SupplyChainAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AlertType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CertificateThumbprint")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Details")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Publisher")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Severity");

                    b.ToTable("SupplyChainAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ThreatReport", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("GeneratedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("OutputFilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("PeriodEnd")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("PeriodStart")
                        .HasColumnType("TEXT");

                    b.Property<string>("ReportType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TopThreatTypes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("TotalFilesScanned")
                        .HasColumnType("INTEGER");

                    b.Property<int>("TotalSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<int>("TotalThreats")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("GeneratedAtUtc");

                    b.HasIndex("ReportType");

                    b.ToTable("ThreatReports", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.TlsCertAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("CertExpiresUtc")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Hostname")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsCnMismatch")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsExpired")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsSelfSigned")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsUnknownCa")
                        .HasColumnType("INTEGER");

                    b.Property<string>("IssuerCn")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Port")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SubjectCn")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ValidationError")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.HasIndex("Hostname");

                    b.ToTable("TlsCertAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.TlsInspectionEvent", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("CapturedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSuspicious")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Method")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("RequestBodySize")
                        .HasColumnType("INTEGER");

                    b.Property<string>("RequestPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ResponseBodySize")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ResponseStatus")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousReason")
                        .HasColumnType("TEXT");

                    b.Property<string>("TargetHost")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("TargetPort")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("CapturedAtUtc");

                    b.HasIndex("IsSuspicious");

                    b.ToTable("TlsInspectionEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.TransactedHollowingAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionMethod")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("ModuleFileExistsOnDisk")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SuspiciousModulePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("TransactedHollowingAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.UefiFinding", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<int>("MatchOffset")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SignatureName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TableName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("UefiFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.UnpackingResult", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectedPacker")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsPacked")
                        .HasColumnType("INTEGER");

                    b.Property<string>("UnpackedFilePath")
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasUnpacked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("UnpackingResults", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.UnsignedBinaryAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSigned")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsTrusted")
                        .HasColumnType("INTEGER");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("UnsignedBinaryAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.UsbDeviceEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("ActionTaken")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("PnpDeviceId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("VendorProductId")
                        .HasColumnType("TEXT");

                    b.Property<bool>("WasAllowed")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("UsbDeviceEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.UserAccountAuditFinding", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AccountName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AuditedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("Classification")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("HasPassword")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsAdmin")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Issue")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("LastLogon")
                        .HasColumnType("TEXT");

                    b.Property<bool>("PasswordNeverExpires")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AuditedAtUtc");

                    b.ToTable("UserAccountAuditFindings", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.VssSnapshotEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreatedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FolderPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsRestoreAction")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SnapshotId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SnapshotPath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("TriggerReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CreatedAtUtc");

                    b.ToTable("VssSnapshotEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.VulnerableSoftwareAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CpeUri")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CveId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<double>("CvssScore")
                        .HasColumnType("REAL");

                    b.Property<string>("CvssVector")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SoftwareName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SoftwareVersion")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CvssScore");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("VulnerableSoftwareAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.WebcamAccessEvent", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("AccessType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DevicePath")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("ProcessId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ProcessName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("WasBlocked")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("WebcamAccessEvents", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.WfpBlock", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("AddedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<ulong>("FilterIdInboundV4")
                        .HasColumnType("INTEGER");

                    b.Property<ulong>("FilterIdOutboundV4")
                        .HasColumnType("INTEGER");

                    b.Property<string>("IpAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsActive")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("IpAddress", "IsActive");

                    b.ToTable("WfpBlocks", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.WmiPersistenceAlert", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("ConsumerName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ConsumerType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilterName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsAcknowledged")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Query")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("QueryLanguage")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ScriptOrCommand")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Severity")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("WmiPersistenceAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.WpadAbuseAlert", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("DetectedAtUtc")
                        .HasColumnType("TEXT");

                    b.Property<string>("DetectionReason")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Hostname")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("QueryType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ResponderIp")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("Severity")
                        .HasColumnType("INTEGER");

                    b.Property<string>("WpadDatContent")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("DetectedAtUtc");

                    b.ToTable("WpadAbuseAlerts", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.YaraMatch", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("RuleIdentifier")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<Guid>("ScannedFileId")
                        .HasColumnType("TEXT");

                    b.Property<string>("Tags")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScannedFileId");

                    b.ToTable("YaraMatches", (string)null);
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.AdsStreamInfo", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithMany()
                        .HasForeignKey("ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.EmailScanResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithMany()
                        .HasForeignKey("ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.FileMetadataAnalysisResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithOne("FileMetadata")
                        .HasForeignKey("PerSourceAntivirus.Domain.Entities.FileMetadataAnalysisResult", "ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.HashReputationResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithOne("HashReputation")
                        .HasForeignKey("PerSourceAntivirus.Domain.Entities.HashReputationResult", "ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.OfficeMacroAnalysisResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithOne("OfficeMacro")
                        .HasForeignKey("PerSourceAntivirus.Domain.Entities.OfficeMacroAnalysisResult", "ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PdfScanResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithMany()
                        .HasForeignKey("ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeAnalysisResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithOne("PeAnalysis")
                        .HasForeignKey("PerSourceAntivirus.Domain.Entities.PeAnalysisResult", "ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeSection", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.PeAnalysisResult", "PeAnalysisResult")
                        .WithMany("Sections")
                        .HasForeignKey("PeAnalysisResultId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("PeAnalysisResult");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScriptAnalysisResult", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithOne("ScriptAnalysis")
                        .HasForeignKey("PerSourceAntivirus.Domain.Entities.ScriptAnalysisResult", "ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.YaraMatch", b =>
                {
                    b.HasOne("PerSourceAntivirus.Domain.Entities.ScannedFile", "ScannedFile")
                        .WithMany("YaraMatches")
                        .HasForeignKey("ScannedFileId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("ScannedFile");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.PeAnalysisResult", b =>
                {
                    b.Navigation("Sections");
                });

            modelBuilder.Entity("PerSourceAntivirus.Domain.Entities.ScannedFile", b =>
                {
                    b.Navigation("FileMetadata");

                    b.Navigation("HashReputation");

                    b.Navigation("OfficeMacro");

                    b.Navigation("PeAnalysis");

                    b.Navigation("ScriptAnalysis");

                    b.Navigation("YaraMatches");
                });
#pragma warning restore 612, 618
        }
    }
}
