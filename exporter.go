package main

import (
    "bufio"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Définition des métriques Prometheus
var (
    // Métrique pour les logiciels installés
    installedSoftwareGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "installed_software_info",
            Help: "Information about installed software",
        },
        []string{"name", "version"},
    )

    // Métrique pour les ports ouverts
    openPortsGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "open_ports_info",
            Help: "Information about open ports",
        },
        []string{"protocol", "port", "address", "pid", "process", "interface"},
    )

    // Métrique pour les ports ouverts par firewalld
    firewalldPortsGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "firewalld_ports_info",
            Help: "Information about firewalld open ports",
        },
        []string{"port", "protocol", "zone"},
    )
)

func init() {
    // Enregistrement des métriques auprès de Prometheus
    prometheus.MustRegister(installedSoftwareGauge)
    prometheus.MustRegister(openPortsGauge)
    prometheus.MustRegister(firewalldPortsGauge)
}

func main() {
    // Collecte initiale des données
    collectData()

    // Exposer l'endpoint /metrics
    http.Handle("/metrics", promhttp.Handler())
    fmt.Println("Serveur en écoute sur le port 9100 pour l'endpoint /metrics")
    if err := http.ListenAndServe(":9100", nil); err != nil {
        fmt.Fprintf(os.Stderr, "Erreur lors du démarrage du serveur HTTP : %v\n", err)
        os.Exit(1)
    }
}

func collectData() {
    // Collecter les logiciels installés
    if err := collectInstalledSoftware(); err != nil {
        fmt.Fprintf(os.Stderr, "Erreur lors de la collecte des logiciels installés : %v\n", err)
    }

    // Collecter les ports ouverts
    if err := collectOpenPorts(); err != nil {
        fmt.Fprintf(os.Stderr, "Erreur lors de la collecte des ports ouverts : %v\n", err)
    }

    // Collecter les ports firewalld
    if err := collectFirewalldOpenPorts(); err != nil {
        fmt.Fprintf(os.Stderr, "Erreur lors de la collecte des ports firewalld : %v\n", err)
    }
}

// collectInstalledSoftware collecte la liste des logiciels installés avec leurs versions
func collectInstalledSoftware() error {
    // Vérifier si RPM est disponible
    if _, err := exec.LookPath("rpm"); err == nil {
        // Systèmes basés sur RPM
        cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}\n")
        output, err := cmd.Output()
        if err != nil {
            return err
        }
        lines := strings.Split(string(output), "\n")
        for _, line := range lines {
            if line == "" {
                continue
            }
            parts := strings.Split(line, "|")
            if len(parts) != 2 {
                continue
            }
            name := parts[0]
            version := parts[1]
            installedSoftwareGauge.WithLabelValues(name, version).Set(1)
        }
    } else if _, err := exec.LookPath("dpkg-query"); err == nil {
        // Systèmes basés sur DEB
        cmd := exec.Command("dpkg-query", "-W", "-f=${Package}|${Version}\n")
        output, err := cmd.Output()
        if err != nil {
            return err
        }
        lines := strings.Split(string(output), "\n")
        for _, line := range lines {
            if line == "" {
                continue
            }
            parts := strings.Split(line, "|")
            if len(parts) != 2 {
                continue
            }
            name := parts[0]
            version := parts[1]
            installedSoftwareGauge.WithLabelValues(name, version).Set(1)
        }
    } else {
        return fmt.Errorf("ni RPM ni dpkg-query n'est disponible sur ce système")
    }

    return nil
}

// collectOpenPorts collecte la liste des ports ouverts et des processus associés
func collectOpenPorts() error {
    protocols := []string{"tcp", "udp"}

    for _, protocol := range protocols {
        cmd := exec.Command("ss", "-H", "-lpn", fmt.Sprintf("--%s", protocol))
        output, err := cmd.Output()
        if err != nil {
            return err
        }

        scanner := bufio.NewScanner(strings.NewReader(string(output)))
        for scanner.Scan() {
            line := scanner.Text()
            if line == "" {
                continue
            }
            fields := strings.Fields(line)
            if len(fields) < 5 {
                continue
            }

            localAddressPort := fields[4]
            pidProcess := fields[len(fields)-1]

            address, port := parseAddressPort(localAddressPort)
            pid, process := parsePIDProcess(pidProcess)
            iface := getInterface(address)

            openPortsGauge.WithLabelValues(protocol, port, address, pid, process, iface).Set(1)
        }
    }

    return nil
}

// collectFirewalldOpenPorts collecte la liste des ports ouverts par firewalld
func collectFirewalldOpenPorts() error {
    if _, err := exec.LookPath("firewall-cmd"); err != nil {
        return fmt.Errorf("firewall-cmd n'est pas disponible sur ce système")
    }

    // Obtenir la liste des zones
    cmd := exec.Command("firewall-cmd", "--get-zones")
    output, err := cmd.Output()
    if err != nil {
        return err
    }

    zones := strings.Fields(string(output))

    for _, zone := range zones {
        cmd := exec.Command("firewall-cmd", "--zone", zone, "--list-ports")
        output, err := cmd.Output()
        if err != nil {
            continue
        }
        ports := strings.Fields(string(output))
        for _, portProto := range ports {
            parts := strings.Split(portProto, "/")
            if len(parts) != 2 {
                continue
            }
            port := parts[0]
            protocol := parts[1]
            firewalldPortsGauge.WithLabelValues(port, protocol, zone).Set(1)
        }
    }

    return nil
}

// parseAddressPort extrait l'adresse et le port à partir de la chaîne fournie
func parseAddressPort(addrPort string) (string, string) {
    if strings.Contains(addrPort, "[") {
        // IPv6
        parts := strings.Split(addrPort, "]:")
        address := strings.TrimPrefix(parts[0], "[")
        port := parts[1]
        return address, port
    } else {
        // IPv4
        parts := strings.Split(addrPort, ":")
        address := parts[0]
        port := parts[1]
        return address, port
    }
}

// parsePIDProcess extrait le PID et le nom du processus à partir de la chaîne fournie
func parsePIDProcess(pidProc string) (string, string) {
    if pidProc == "-" {
        return "", ""
    }
    pid := ""
    process := ""

    if strings.HasPrefix(pidProc, "users:(") {
        pidProc = strings.TrimPrefix(pidProc, "users:(")
        pidProc = strings.TrimSuffix(pidProc, ")")
    }

    parts := strings.Split(pidProc, ",")
    for _, part := range parts {
        if strings.Contains(part, "pid=") {
            pid = strings.TrimPrefix(part, "pid=")
            pid = strings.Trim(pid, "\"")
        } else if strings.Contains(part, "exe=") {
            process = strings.TrimPrefix(part, "exe=")
            process = strings.Trim(process, "\"")
            process = filepath.Base(process)
        }
    }

    return pid, process
}

// getInterface détermine le nom de l'interface associée à une adresse IP
func getInterface(address string) string {
    ifaces, err := net.Interfaces()
    if err != nil {
        return ""
    }

    for _, iface := range ifaces {
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            if ip.String() == address {
                return iface.Name
            }
        }
    }
    return ""
}
