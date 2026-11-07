package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "Server base URL")
	format := flag.String("format", "json", "Output format for report (json or markdown)")
	authorized := flag.Bool("authorized", false, "Confirm you are authorized to audit the target repository (required for create)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	switch command {
	case "create":
		if len(args) < 2 {
			fmt.Println("Usage: cli --authorized create <repository_ref> [revision]")
			os.Exit(1)
		}
		repo := args[1]
		rev := "HEAD"
		if len(args) >= 3 {
			rev = args[2]
		}
		if !*authorized {
			fmt.Println("Refusing to create job: pass --authorized to confirm you are permitted to audit this repository.")
			os.Exit(1)
		}
		createJob(*serverURL, repo, rev)

	case "list":
		listJobs(*serverURL)

	case "inspect":
		if len(args) < 2 {
			fmt.Println("Usage: cli inspect <job_id>")
			os.Exit(1)
		}
		inspectJob(*serverURL, args[1])

	case "cancel":
		if len(args) < 2 {
			fmt.Println("Usage: cli cancel <job_id>")
			os.Exit(1)
		}
		cancelJob(*serverURL, args[1])

	case "report":
		if len(args) < 2 {
			fmt.Println("Usage: cli report <job_id> [--format json|markdown]")
			os.Exit(1)
		}
		// Go's flag package stops at the first positional arg, so also accept
		// `report <id> --format markdown` (as documented) after the subcommand.
		reportFormat := *format
		for i := 2; i < len(args); i++ {
			switch {
			case (args[i] == "--format" || args[i] == "-format") && i+1 < len(args):
				reportFormat = args[i+1]
				i++
			case strings.HasPrefix(args[i], "--format="):
				reportFormat = strings.TrimPrefix(args[i], "--format=")
			}
		}
		fetchReport(*serverURL, args[1], reportFormat)

	case "health":
		checkHealth(*serverURL)

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Autonomous Vulnerability Research Platform CLI")
	fmt.Println("Usage: cli [flags] <command> [args...]")
	fmt.Println("\nCommands:")
	fmt.Println("  create <repo> [rev]              Create a new research job")
	fmt.Println("  list                             List all research jobs")
	fmt.Println("  inspect <job_id>                 View job details and status")
	fmt.Println("  report <job_id> [--format md]    Retrieve audit report (json or markdown)")
	fmt.Println("  cancel <job_id>                  Cancel an active job")
	fmt.Println("  health                           Query server health probes")
}

func createJob(server, repo, rev string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"repository_ref":      repo,
		"repository_revision": rev,
		"authorization_scope": map[string]interface{}{"authorized": true},
	})

	resp, err := http.Post(server+"/api/v1/jobs", "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Printf("Error creating job: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Job Created (%d):\n%s\n", resp.StatusCode, string(body))
}

func listJobs(server string) {
	resp, err := http.Get(server + "/api/v1/jobs")
	if err != nil {
		fmt.Printf("Error listing jobs: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Jobs:\n%s\n", string(body))
}

func inspectJob(server, jobID string) {
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/jobs/%s", server, jobID))
	if err != nil {
		fmt.Printf("Error inspecting job: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Job Details:\n%s\n", string(body))
}

func cancelJob(server, jobID string) {
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/jobs/%s/cancel", server, jobID), "application/json", nil)
	if err != nil {
		fmt.Printf("Error cancelling job: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Cancel Status (%d): %s\n", resp.StatusCode, string(body))
}

func fetchReport(server, jobID, format string) {
	url := fmt.Sprintf("%s/api/v1/jobs/%s/report", server, jobID)
	if format == "markdown" || format == "md" {
		url += "?format=markdown"
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching report: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func checkHealth(server string) {
	resp, err := http.Get(server + "/health/ready")
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status (%d):\n%s\n", resp.StatusCode, string(body))
}
