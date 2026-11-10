
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";

const mockCy = {
  on: vi.fn(),
  destroy: vi.fn(),
  elements: vi.fn((selector?: string) => ({
  length: selector === ".path-highlight" ? 1 : 0,
  removeClass: vi.fn().mockReturnThis(),
  addClass: vi.fn().mockReturnThis(),
})),
  nodes: vi.fn(() => ({
  filter: vi.fn(() => ({
    length: 1,
    removeClass: vi.fn().mockReturnThis(),
    addClass: vi.fn().mockReturnThis(),
    connectedEdges: vi.fn(() => ({
      removeClass: vi.fn().mockReturnThis(),
    })),
  })),
})),
  edges: vi.fn(() => ({
    filter: vi.fn(() => ({
      forEach: vi.fn(),
    })),
  })),
  getElementById: vi.fn(() => ({
  removeClass: vi.fn().mockReturnThis(),
  addClass: vi.fn().mockReturnThis(),
})),
  animate: vi.fn(),
  layout: vi.fn(() => ({ run: vi.fn() })),
  fit: vi.fn(),
};

vi.mock("cytoscape", () => ({
  default: vi.fn(() => mockCy),
}));

describe("NexaGraph AI Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
        }),
      })
    );
  });

  it("renders the dashboard after loading graph data", async () => {
    render(<App />);

    expect(
      screen.getByText("Loading enterprise graph...")
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("SYSTEM ONLINE")).toBeInTheDocument();
    });

    expect(screen.getByText("NEXAGRAPH AI")).toBeInTheDocument();
    expect(screen.getByText("Manage Enterprise Graph")).toBeInTheDocument();
    expect(screen.getByText("Attack Path Analysis")).toBeInTheDocument();
    expect(screen.getByText("Remediation Simulator")).toBeInTheDocument();
    expect(screen.getByText("Enterprise Attack Graph")).toBeInTheDocument();
  });

it("displays an error when the backend is unavailable", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockRejectedValue(new Error("Network error"))
  );

  render(<App />);

  expect(await screen.findByText("BACKEND UNAVAILABLE")).toBeInTheDocument();

  expect(
    screen.getByText("Network error")
  ).toBeInTheDocument();
});

it("analyzes attack paths and displays the results", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                ip: "0.0.0.0",
                criticality: "Low",
                exposed: "Yes",
                compromised: "No",
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                ip: "10.0.0.6",
                criticality: "Critical",
                exposed: "No",
                compromised: "No",
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
                protocol: "TCP",
              },
            ],
          }),
        };
      }

      if (url.endsWith("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [
                  {
                    id: "A01",
                    name: "Internet",
                    type: "External",
                    ip: "0.0.0.0",
                    criticality: "Low",
                    exposed: "Yes",
                    compromised: "No",
                  },
                  {
                    id: "A06",
                    name: "Customer-DB",
                    type: "Database",
                    ip: "10.0.0.6",
                    criticality: "Critical",
                    exposed: "No",
                    compromised: "No",
                  },
                ],
                connections: [
                  {
                    source: "A01",
                    target: "A06",
                    relationship: "CONNECTS",
                    protocol: "TCP",
                  },
                ],
                risk_score: 90,
                risk_level: "Critical",
              },
            ],
            total_paths: 1,
            max_paths_reached: false,
            scoring_note: "Test risk scoring note.",
          }),
        };
      }

      throw new Error(`Unexpected API request: ${url}`);
    })
  );

  render(<App />);

  const analyzeButton = await screen.findByRole("button", {
    name: "Analyze Attack Paths",
  });

  await user.click(analyzeButton);

  expect(await screen.findByText("Attack Path 1")).toBeInTheDocument();
  expect(screen.getByText("Critical Risk")).toBeInTheDocument();
  expect(screen.getByText("90", { exact: true })).toBeInTheDocument();
  expect(screen.getByText("Internet")).toBeInTheDocument();
  expect(screen.getByText("Customer-DB")).toBeInTheDocument();
  expect(screen.getByText("Paths Found").parentElement).toHaveTextContent("1");
});

it("runs an asset isolation simulation and displays the results", async () => {
  const user = userEvent.setup();

  const mockSimulationResult = {
    action_type: "isolate-asset",
    simulated_only: true,
    database_modified: false,
    before: {
      total_paths: 1,
      paths: [],
    },
    after: {
      total_paths: 0,
      paths: [],
    },
    paths_eliminated: 1,
    highest_risk_before: 90,
    highest_risk_after: 0,
    risk_score_reduction: 90,
    recommendations: [],
    scoring_note: "Test simulation scoring note.",
  };

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/simulate-remediation")) {
      return {
        ok: true,
        json: async () => mockSimulationResult,
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  // Select the asset to isolate.
  await user.selectOptions(
    screen.getByLabelText("Asset to isolate"),
    "A06"
  );

  // Run the simulation.
  await user.click(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  );

  // Verify the simulation API request.
  await waitFor(() => {
    const simulationCall = fetchMock.mock.calls.find(
      ([url]) => String(url).endsWith("/simulate-remediation")
    );

    expect(simulationCall).toBeDefined();

    const requestOptions = simulationCall![1] as RequestInit;

    expect(JSON.parse(requestOptions.body as string)).toEqual({
      action_type: "isolate-asset",
      target_id: "A06",
    });
  });

  // Verify the simulation results.
  expect(await screen.findByText("DATABASE UNCHANGED")).toBeInTheDocument();
  expect(screen.getByText("Paths Before").parentElement).toHaveTextContent("1");
  expect(screen.getByText("Paths After").parentElement).toHaveTextContent("0");
  expect(screen.getByText("Paths Eliminated").parentElement).toHaveTextContent("1");
});


it("runs a connection removal simulation and displays the results", async () => {
  const user = userEvent.setup();

  const mockSimulationResult = {
    action_type: "remove-connection",
    simulated_only: true,
    database_modified: false,
    before: {
      total_paths: 1,
      paths: [],
    },
    after: {
      total_paths: 0,
      paths: [],
    },
    paths_eliminated: 1,
    highest_risk_before: 90,
    highest_risk_after: 0,
    risk_score_reduction: 90,
    recommendations: [],
    scoring_note: "Test connection removal scoring note.",
  };

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/simulate-remediation")) {
      return {
        ok: true,
        json: async () => mockSimulationResult,
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  // Select connection removal.
  await user.selectOptions(
    screen.getByLabelText("Remediation action"),
    "remove-connection"
  );

  // Select the first connection.
  await user.selectOptions(
    screen.getByLabelText("Connection to remove"),
    "0"
  );

  // Run the simulation.
  await user.click(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  );

  // Verify the request sent to the backend.
  await waitFor(() => {
    const simulationCall = fetchMock.mock.calls.find(
      ([url]) => String(url).endsWith("/simulate-remediation")
    );

    expect(simulationCall).toBeDefined();

    const requestOptions = simulationCall![1] as RequestInit;

    expect(JSON.parse(requestOptions.body as string)).toEqual({
      action_type: "remove-connection",
      source_id: "A01",
      destination_id: "A06",
      relationship: "CONNECTS",
    });
  });

  // Verify simulation results.
  expect(await screen.findByText("DATABASE UNCHANGED")).toBeInTheDocument();
  expect(screen.getByText("Paths Before").parentElement).toHaveTextContent("1");
  expect(screen.getByText("Paths After").parentElement).toHaveTextContent("0");
  expect(screen.getByText("Paths Eliminated").parentElement).toHaveTextContent("1");
});


it("prevents asset isolation when no asset is selected", async () => {
  const user = userEvent.setup();

  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      nodes: [
        {
          id: "A01",
          name: "Internet",
          type: "External",
          ip: "0.0.0.0",
          criticality: "Low",
          exposed: "Yes",
          compromised: "No",
        },
        {
          id: "A06",
          name: "Customer-DB",
          type: "Database",
          ip: "10.0.0.6",
          criticality: "Critical",
          exposed: "No",
          compromised: "No",
        },
      ],
      edges: [
        {
          source: "A01",
          target: "A06",
          relationship: "CONNECTS",
          protocol: "TCP",
        },
      ],
    }),
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  // Leave the asset dropdown at its default empty value.
  expect(screen.getByLabelText("Asset to isolate")).toHaveValue("");

  // The simulation button should be disabled.
  expect(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  ).toBeDisabled();

  // No simulation request should have been sent.
  expect(
    fetchMock.mock.calls.some(([url]) =>
      String(url).endsWith("/simulate-remediation")
    )
  ).toBe(false);
});


it("displays an error when remediation simulation fails", async () => {
  const user = userEvent.setup();

  const errorMessage = "Simulation service unavailable.";

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/simulate-remediation")) {
      return {
        ok: false,
        status: 503,
        json: async () => ({
          detail: errorMessage,
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  await user.selectOptions(
    screen.getByLabelText("Asset to isolate"),
    "A06"
  );

  await user.click(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  );

  // Confirm that the API request was attempted.
  await waitFor(() => {
    expect(
      fetchMock.mock.calls.some(([url]) =>
        String(url).endsWith("/simulate-remediation")
      )
    ).toBe(true);
  });

  // Confirm that the simulation error is displayed.
  expect(
    await screen.findByText(errorMessage)
  ).toBeInTheDocument();
});

it("displays an error when the simulation response is incomplete", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.endsWith("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: "Yes",
                compromised: "No",
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: "No",
                compromised: "No",
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.endsWith("/simulate-remediation")) {
        return {
          ok: true,
          json: async () => ({
            action_type: "isolate-asset",
            simulated_only: true,
            database_modified: false,
            // Intentionally missing before and after.
          }),
        };
      }

      throw new Error(`Unexpected URL: ${url}`);
    })
  );

  render(<App />);

  await user.selectOptions(
    await screen.findByLabelText("Asset to isolate"),
    "A06"
  );

  await user.click(
    screen.getByRole("button", { name: /run full-graph simulation/i })
  );

  expect(
    await screen.findByText(
      "The simulation endpoint returned an unexpected response. Check the backend response schema."
    )
  ).toBeInTheDocument();
});


it("highlights the selected attack path in the graph", async () => {
  const user = userEvent.setup();

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/attack-paths")) {
      return {
        ok: true,
        json: async () => ({
          paths: [
            {
              path: [
                {
                  id: "A01",
                  name: "Internet",
                  type: "External",
                  ip: "0.0.0.0",
                  criticality: "Low",
                  exposed: "Yes",
                  compromised: "No",
                },
                {
                  id: "A06",
                  name: "Customer-DB",
                  type: "Database",
                  ip: "10.0.0.6",
                  criticality: "Critical",
                  exposed: "No",
                  compromised: "No",
                },
              ],
              connections: [
                {
                  source: "A01",
                  target: "A06",
                  relationship: "CONNECTS",
                  protocol: "TCP",
                },
              ],
              risk_score: 90,
              risk_level: "Critical",
            },
          ],
          total_paths: 1,
          max_paths_reached: false,
          scoring_note: "Test risk scoring note.",
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  // Run attack-path analysis.
  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  // Confirm the attack path is displayed.
  const pathCard = await screen.findByRole("button", {
    name: /Attack Path 1/i,
  });

  expect(pathCard).toHaveAttribute("aria-pressed", "false");

  // Select the attack path.
  await user.click(pathCard);

  // Confirm the selected path state.
  expect(pathCard).toHaveAttribute("aria-pressed", "true");
  expect(
    screen.getByText("Currently highlighted in the graph")
  ).toBeInTheDocument();

  // Verify graph highlighting operations.
  expect(mockCy.elements).toHaveBeenCalled();
  expect(mockCy.getElementById).toHaveBeenCalledWith("A01");
  expect(mockCy.getElementById).toHaveBeenCalledWith("A06");
  expect(mockCy.edges).toHaveBeenCalled();
  expect(mockCy.animate).toHaveBeenCalled();
});


it("updates graph highlighting when a different attack path is selected", async () => {
  const user = userEvent.setup();

  const internet = {
    id: "A01",
    name: "Internet",
    type: "External",
    ip: "0.0.0.0",
    criticality: "Low",
    exposed: "Yes",
    compromised: "No",
  };

  const webServer = {
    id: "A02",
    name: "Web-Server",
    type: "Server",
    ip: "10.0.0.2",
    criticality: "High",
    exposed: "Yes",
    compromised: "No",
  };

  const customerDB = {
    id: "A06",
    name: "Customer-DB",
    type: "Database",
    ip: "10.0.0.6",
    criticality: "Critical",
    exposed: "No",
    compromised: "No",
  };

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [internet, webServer, customerDB],
          edges: [
            {
              source: "A01",
              target: "A02",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
            {
              source: "A02",
              target: "A06",
              relationship: "ACCESSES",
              protocol: "TCP",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/attack-paths")) {
      return {
        ok: true,
        json: async () => ({
          paths: [
            {
              path: [internet, webServer],
              connections: [
                {
                  source: "A01",
                  target: "A02",
                  relationship: "CONNECTS",
                  protocol: "TCP",
                },
              ],
              risk_score: 75,
              risk_level: "High",
            },
            {
              path: [webServer, customerDB],
              connections: [
                {
                  source: "A02",
                  target: "A06",
                  relationship: "ACCESSES",
                  protocol: "TCP",
                },
              ],
              risk_score: 90,
              risk_level: "Critical",
            },
          ],
          total_paths: 2,
          max_paths_reached: false,
          scoring_note: "Test risk scoring note.",
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  const firstPath = await screen.findByRole("button", {
    name: /Attack Path 1/i,
  });

  const secondPath = await screen.findByRole("button", {
    name: /Attack Path 2/i,
  });

  // Select the first attack path.
  await user.click(firstPath);

  expect(firstPath).toHaveAttribute("aria-pressed", "true");
  expect(secondPath).toHaveAttribute("aria-pressed", "false");

  // Select the second attack path.
  await user.click(secondPath);

  expect(firstPath).toHaveAttribute("aria-pressed", "false");
  expect(secondPath).toHaveAttribute("aria-pressed", "true");

  // Verify that the second path's Customer-DB node was highlighted.
  expect(mockCy.getElementById).toHaveBeenCalledWith("A06");
});


it("handles an empty attack-path response", async () => {
  const user = userEvent.setup();

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [],
        }),
      };
    }

    if (url.endsWith("/attack-paths")) {
      return {
        ok: true,
        json: async () => ({
          paths: [],
          total_paths: 0,
          max_paths_reached: false,
          scoring_note: "Test risk scoring note.",
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  // Confirm that attack-path analysis completed.
  // Confirm that attack-path analysis completed.
// Confirm that attack-path analysis completed.
await waitFor(() => {
  const attackPathRequest = fetchMock.mock.calls.some(
    ([url]) =>
      typeof url === "string" && url.endsWith("/attack-paths")
  );

  expect(attackPathRequest).toBe(true);
});

  // Confirm that no attack-path cards are displayed.
  expect(
    screen.queryByRole("button", { name: /Attack Path \d+/i })
  ).not.toBeInTheDocument();
});


it("displays the correct risk level and score for a High-risk attack path", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: "Yes",
                compromised: "No",
              },
              {
                id: "A02",
                name: "Web-Server",
                type: "Server",
                criticality: "High",
                exposed: "Yes",
                compromised: "No",
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A02",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.endsWith("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [
                  {
                    id: "A01",
                    name: "Internet",
                    type: "External",
                    criticality: "Low",
                    exposed: "Yes",
                    compromised: "No",
                  },
                  {
                    id: "A02",
                    name: "Web-Server",
                    type: "Server",
                    criticality: "High",
                    exposed: "Yes",
                    compromised: "No",
                  },
                ],
                connections: [
                  {
                    source: "A01",
                    target: "A02",
                    relationship: "CONNECTS",
                  },
                ],
                risk_score: 75,
                risk_level: "High",
              },
            ],
            total_paths: 1,
            max_paths_reached: false,
            scoring_note: "Test risk scoring note.",
          }),
        };
      }

      throw new Error(`Unexpected API request: ${url}`);
    })
  );

  render(<App />);

  const analyzeButton = await screen.findByRole("button", {
    name: "Analyze Attack Paths",
  });

  await user.click(analyzeButton);

  expect(await screen.findByText("Attack Path 1")).toBeInTheDocument();
  expect(screen.getByText("High Risk")).toBeInTheDocument();
  expect(screen.getByText("75", { exact: true })).toBeInTheDocument();
  expect(screen.getByText("Internet")).toBeInTheDocument();
  expect(screen.getByText("Web-Server")).toBeInTheDocument();
});


it("displays all four attack-path risk levels correctly", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                ip: "0.0.0.0",
                criticality: "Low",
                exposed: "Yes",
                compromised: "No",
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                ip: "10.0.0.6",
                criticality: "Critical",
                exposed: "No",
                compromised: "No",
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
                protocol: "TCP",
              },
            ],
          }),
        };
      }

      if (url.endsWith("/attack-paths")) {
        const createPath = (score: number, level: string) => ({
          path: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              ip: "0.0.0.0",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              ip: "10.0.0.6",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          connections: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
              protocol: "TCP",
            },
          ],
          risk_score: score,
          risk_level: level,
        });

        return {
          ok: true,
          json: async () => ({
            paths: [
              createPath(90, "Critical"),
              createPath(75, "High"),
              createPath(50, "Medium"),
              createPath(20, "Low"),
            ],
            total_paths: 4,
            max_paths_reached: false,
            scoring_note: "Test risk scoring note.",
          }),
        };
      }

      throw new Error(`Unexpected API request: ${url}`);
    })
  );

  render(<App />);

  const analyzeButton = await screen.findByRole("button", {
    name: "Analyze Attack Paths",
  });

  await user.click(analyzeButton);

  expect(await screen.findByText("Attack Path 1")).toBeInTheDocument();
  expect(screen.getByText("Attack Path 2")).toBeInTheDocument();
  expect(screen.getByText("Attack Path 3")).toBeInTheDocument();
  expect(screen.getByText("Attack Path 4")).toBeInTheDocument();

  expect(screen.getByText("Critical Risk")).toBeInTheDocument();
  expect(screen.getByText("High Risk")).toBeInTheDocument();
  expect(screen.getByText("Medium Risk")).toBeInTheDocument();
  expect(screen.getByText("Low Risk")).toBeInTheDocument();

  expect(screen.getByText("90", { exact: true })).toBeInTheDocument();
  expect(screen.getByText("75", { exact: true })).toBeInTheDocument();
  expect(screen.getByText("50", { exact: true })).toBeInTheDocument();
  expect(screen.getByText("20", { exact: true })).toBeInTheDocument();
});

it("displays the correct risk levels at all score boundaries", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: "Yes",
                compromised: "No",
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: "No",
                compromised: "No",
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.endsWith("/attack-paths")) {
        const createPath = (
          score: number,
          level: "Low" | "Medium" | "High" | "Critical"
        ) => ({
          path: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          connections: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
            },
          ],
          risk_score: score,
          risk_level: level,
        });

        return {
          ok: true,
          json: async () => ({
            paths: [
              createPath(34, "Low"),
              createPath(35, "Medium"),
              createPath(59, "Medium"),
              createPath(60, "High"),
              createPath(79, "High"),
              createPath(80, "Critical"),
            ],
            total_paths: 6,
            max_paths_reached: false,
            scoring_note: "Test risk boundary note.",
          }),
        };
      }

      throw new Error(`Unexpected API request: ${url}`);
    })
  );

  render(<App />);

  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  // Verify all six attack paths are displayed.
  for (let i = 1; i <= 6; i++) {
    expect(
      await screen.findByText(`Attack Path ${i}`)
    ).toBeInTheDocument();
  }

  // Verify the risk scores.
  for (const score of [34, 35, 59, 60, 79, 80]) {
    expect(
      screen.getByText(String(score), { exact: true })
    ).toBeInTheDocument();
  }

  // Verify the corresponding risk levels.
  expect(screen.getByText("Low Risk")).toBeInTheDocument();
  expect(screen.getAllByText("Medium Risk")).toHaveLength(2);
  expect(screen.getAllByText("High Risk")).toHaveLength(2);
  expect(screen.getByText("Critical Risk")).toBeInTheDocument();
});


it("displays an error when attack-path analysis fails", async () => {
  const user = userEvent.setup();

  const errorMessage = "Attack-path service unavailable.";

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/attack-paths")) {
      return {
        ok: false,
        status: 503,
        json: async () => ({
          detail: errorMessage,
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  // Verify that the API error is displayed.
  expect(
    await screen.findByText(errorMessage)
  ).toBeInTheDocument();

  // Verify that no attack-path cards are displayed.
  expect(
    screen.queryByRole("button", {
      name: /Attack Path \d+/i,
    })
  ).not.toBeInTheDocument();

  // Verify that the loading state has ended.
  expect(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  ).toBeEnabled();
});


it("displays an error when the attack-path response is invalid", async () => {
  const user = userEvent.setup();

  const errorMessage =
    "The attack-path endpoint returned an unexpected response.";

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "A01",
              name: "Internet",
              type: "External",
              criticality: "Low",
              exposed: "Yes",
              compromised: "No",
            },
            {
              id: "A06",
              name: "Customer-DB",
              type: "Database",
              criticality: "Critical",
              exposed: "No",
              compromised: "No",
            },
          ],
          edges: [
            {
              source: "A01",
              target: "A06",
              relationship: "CONNECTS",
            },
          ],
        }),
      };
    }

    if (url.endsWith("/attack-paths")) {
      return {
        ok: true,
        json: async () => ({
          total_paths: 1,
          max_paths_reached: false,
          scoring_note: "Test response with missing paths.",
          // Intentionally missing the paths array.
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await user.click(
    await screen.findByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  // Verify that the invalid response error is displayed.
  expect(
    await screen.findByText(errorMessage)
  ).toBeInTheDocument();

  // Verify that no attack-path cards are displayed.
  expect(
    screen.queryByRole("button", {
      name: /Attack Path \d+/i,
    })
  ).not.toBeInTheDocument();

  // Verify that the loading state has ended.
  expect(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  ).toBeEnabled();
});


it("clears previous attack-path results when re-analysis fails", async () => {
  const user = userEvent.setup();

  let requestCount = 0;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        requestCount++;

        if (requestCount === 1) {
          return {
            ok: true,
            json: async () => ({
              paths: [
                {
                  path: ["A01", "A06"],
                  risk_score: 90,
                  risk_level: "Critical",
                },
              ],
            }),
          };
        }

        return {
          ok: false,
          status: 503,
          json: async () => ({
            detail: "Attack-path service unavailable.",
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  

  const analyzeButton = screen.getByRole("button", {
  name: "Analyze Attack Paths",
});

  await user.click(analyzeButton);

  await waitFor(() => {
  expect(screen.getByText("90")).toBeInTheDocument();
});

  await user.click(analyzeButton);

  await waitFor(() => {
    expect(
      screen.getByText("Attack-path service unavailable.")
    ).toBeInTheDocument();
  });

  expect(screen.queryByText("90")).not.toBeInTheDocument();
});

it("re-enables the Analyze Attack Paths button after a failed request", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: false,
          status: 503,
          json: async () => ({
            detail: "Attack-path service unavailable.",
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  const analyzeButton = screen.getByRole("button", {
    name: "Analyze Attack Paths",
  });

  await user.click(analyzeButton);

  await waitFor(() => {
    expect(
      screen.getByText("Attack-path service unavailable.")
    ).toBeInTheDocument();
  });

  expect(analyzeButton).toBeEnabled();
});


it("clears the previous error after a successful attack-path analysis", async () => {
  const user = userEvent.setup();
  let requestCount = 0;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        requestCount++;

        if (requestCount === 1) {
          return {
            ok: false,
            status: 503,
            json: async () => ({
              detail: "Attack-path service unavailable.",
            }),
          };
        }

        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: ["A01", "A06"],
                risk_score: 90,
                risk_level: "Critical",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  const analyzeButton = screen.getByRole("button", {
    name: "Analyze Attack Paths",
  });

  // First request: failure
  await user.click(analyzeButton);

  await waitFor(() => {
    expect(
      screen.getByText("Attack-path service unavailable.")
    ).toBeInTheDocument();
  });

  // Second request: success
  await user.click(analyzeButton);

  await waitFor(() => {
    expect(screen.getByText("90")).toBeInTheDocument();
  });

  expect(
    screen.queryByText("Attack-path service unavailable.")
  ).not.toBeInTheDocument();
});

it("updates attack-path results after a second successful analysis", async () => {
  const user = userEvent.setup();
  let requestCount = 0;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A06",
                relationship: "CONNECTS",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        requestCount++;

        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path:
                  requestCount === 1
                    ? ["A01", "A06"]
                    : ["A06", "A01"],
                risk_score: requestCount === 1 ? 90 : 65,
                risk_level: requestCount === 1 ? "Critical" : "High",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  const analyzeButton = screen.getByRole("button", {
    name: "Analyze Attack Paths",
  });

  await user.click(analyzeButton);

  await waitFor(() => {
    expect(screen.getByText("90")).toBeInTheDocument();
  });

  await user.click(analyzeButton);

  await waitFor(() => {
    expect(screen.getByText("65")).toBeInTheDocument();
  });

  expect(screen.queryByText("90")).not.toBeInTheDocument();
});

it("preserves attack-path results when selecting a different path", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A02",
                name: "Web-Server",
                type: "Server",
                criticality: "High",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A02",
                relationship: "CONNECTS",
              },
              {
                source: "A02",
                target: "A06",
                relationship: "ACCESSES",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
  {
    path: [
      { id: "A01", name: "Internet" },
      { id: "A02", name: "Web-Server" },
      { id: "A06", name: "Customer-DB" },
    ],
    connections: [
      {
        source: "A01",
        destination: "A02",
        target: "A02",
        relationship: "CONNECTS",
      },
      {
        source: "A02",
        destination: "A06",
        target: "A06",
        relationship: "ACCESSES",
      },
    ],
    risk_score: 90,
    risk_level: "Critical",
  },
  {
    path: [
      { id: "A02", name: "Web-Server" },
      { id: "A06", name: "Customer-DB" },
    ],
    connections: [
      {
        source: "A02",
        destination: "A06",
        target: "A06",
        relationship: "ACCESSES",
      },
    ],
    risk_score: 65,
    risk_level: "High",
  },
],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  await user.click(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  await waitFor(() => {
    expect(screen.getByText("90")).toBeInTheDocument();
    expect(screen.getByText("65")).toBeInTheDocument();
  });

  const firstPath = screen.getByText("90");
  const secondPath = screen.getByText("65");

 const firstCard = firstPath.closest(".attack-path-card");
const secondCard = secondPath.closest(".attack-path-card");

  expect(firstCard).not.toBeNull();
  expect(secondCard).not.toBeNull();

  await user.click(secondCard!);

  expect(screen.getByText("90")).toBeInTheDocument();
  expect(screen.getByText("65")).toBeInTheDocument();
});

it("handles an attack path with no connections", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
            ],
            edges: [],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [{ id: "A01", name: "Internet" }],
                connections: [],
                risk_score: 40,
                risk_level: "Medium",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  await user.click(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  await waitFor(() => {
    expect(screen.getByText("40")).toBeInTheDocument();
  });

  const pathCard = screen.getByText("40").closest(".attack-path-card");

  expect(pathCard).not.toBeNull();

  await user.click(pathCard!);

  expect(screen.getByText("40")).toBeInTheDocument();
  expect(screen.getByText("Currently highlighted in the graph")).toBeInTheDocument();
});

it("handles an attack path containing a single asset", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
            ],
            edges: [],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [{ id: "A01", name: "Internet" }],
                connections: [],
                risk_score: 40,
                risk_level: "Medium",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  await user.click(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  await waitFor(() => {
    expect(screen.getByText("40")).toBeInTheDocument();
  });

  const pathCard = screen.getByText("40").closest(".attack-path-card");

  expect(pathCard).not.toBeNull();
  expect(pathCard).toHaveTextContent("1 assets");
  expect(pathCard).toHaveTextContent("0 hops");

  await user.click(pathCard!);

  expect(
    screen.getByText("Currently highlighted in the graph")
  ).toBeInTheDocument();
});

it("displays and selects multiple attack paths with different risk levels", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A02",
                name: "Web-Server",
                type: "Server",
                criticality: "High",
                exposed: true,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              {
                source: "A01",
                target: "A02",
                relationship: "CONNECTS",
              },
              {
                source: "A02",
                target: "A06",
                relationship: "ACCESSES",
              },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [
                  { id: "A01", name: "Internet" },
                  { id: "A02", name: "Web-Server" },
                  { id: "A06", name: "Customer-DB" },
                ],
                connections: [
                  {
                    source: "A01",
                    destination: "A02",
                    target: "A02",
                    relationship: "CONNECTS",
                  },
                  {
                    source: "A02",
                    destination: "A06",
                    target: "A06",
                    relationship: "ACCESSES",
                  },
                ],
                risk_score: 90,
                risk_level: "Critical",
              },
              {
                path: [
                  { id: "A02", name: "Web-Server" },
                  { id: "A06", name: "Customer-DB" },
                ],
                connections: [
                  {
                    source: "A02",
                    destination: "A06",
                    target: "A06",
                    relationship: "ACCESSES",
                  },
                ],
                risk_score: 65,
                risk_level: "High",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  await user.click(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  await waitFor(() => {
    expect(screen.getByText("90")).toBeInTheDocument();
    expect(screen.getByText("65")).toBeInTheDocument();
  });

  const pathCards = screen
  .getAllByRole("button")
  .filter((button) =>
    button.querySelector(".attack-path-heading strong")
  );

  expect(pathCards.length).toBe(2);

  expect(pathCards[0]).toHaveAttribute("aria-pressed", "false");
  expect(pathCards[1]).toHaveAttribute("aria-pressed", "false");

  await user.click(pathCards[0]);

  expect(pathCards[0]).toHaveAttribute("aria-pressed", "true");
  expect(pathCards[1]).toHaveAttribute("aria-pressed", "false");

  await user.click(pathCards[1]);

  expect(pathCards[0]).toHaveAttribute("aria-pressed", "false");
  expect(pathCards[1]).toHaveAttribute("aria-pressed", "true");

  expect(screen.getByText("90")).toBeInTheDocument();
  expect(screen.getByText("65")).toBeInTheDocument();
});

it("handles multiple attack paths that share an asset", async () => {
  const user = userEvent.setup();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/graph")) {
        return {
          ok: true,
          json: async () => ({
            nodes: [
              {
                id: "A01",
                name: "Internet",
                type: "External",
                criticality: "Low",
                exposed: true,
                compromised: false,
              },
              {
                id: "A02",
                name: "Web-Server",
                type: "Server",
                criticality: "High",
                exposed: true,
                compromised: false,
              },
              {
                id: "A03",
                name: "App-Server",
                type: "Server",
                criticality: "High",
                exposed: false,
                compromised: false,
              },
              {
                id: "A06",
                name: "Customer-DB",
                type: "Database",
                criticality: "Critical",
                exposed: false,
                compromised: false,
              },
              {
                id: "A07",
                name: "Admin-PC",
                type: "Endpoint",
                criticality: "High",
                exposed: false,
                compromised: false,
              },
            ],
            edges: [
              { source: "A01", target: "A02", relationship: "CONNECTS" },
              { source: "A02", target: "A03", relationship: "CONNECTS" },
              { source: "A03", target: "A06", relationship: "ACCESSES" },
              { source: "A02", target: "A07", relationship: "CONNECTS" },
            ],
          }),
        };
      }

      if (url.includes("/attack-paths")) {
        return {
          ok: true,
          json: async () => ({
            paths: [
              {
                path: [
                  { id: "A01", name: "Internet" },
                  { id: "A02", name: "Web-Server" },
                  { id: "A03", name: "App-Server" },
                  { id: "A06", name: "Customer-DB" },
                ],
                connections: [
                  {
                    source: "A01",
                    target: "A02",
                    relationship: "CONNECTS",
                  },
                  {
                    source: "A02",
                    target: "A03",
                    relationship: "CONNECTS",
                  },
                  {
                    source: "A03",
                    target: "A06",
                    relationship: "ACCESSES",
                  },
                ],
                risk_score: 90,
                risk_level: "Critical",
              },
              {
                path: [
                  { id: "A01", name: "Internet" },
                  { id: "A02", name: "Web-Server" },
                  { id: "A07", name: "Admin-PC" },
                ],
                connections: [
                  {
                    source: "A01",
                    target: "A02",
                    relationship: "CONNECTS",
                  },
                  {
                    source: "A02",
                    target: "A07",
                    relationship: "CONNECTS",
                  },
                ],
                risk_score: 65,
                risk_level: "High",
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        json: async () => ({}),
      };
    })
  );

  render(<App />);

  await user.click(
    screen.getByRole("button", {
      name: "Analyze Attack Paths",
    })
  );

  await waitFor(() => {
    expect(screen.getByText("90")).toBeInTheDocument();
    expect(screen.getByText("65")).toBeInTheDocument();
  });

  const pathCards = screen
    .getAllByRole("button")
    .filter((button) =>
      button.querySelector(".attack-path-heading strong")
    );

  expect(pathCards).toHaveLength(2);

  expect(pathCards[0]).toHaveTextContent("Critical Risk");
  expect(pathCards[1]).toHaveTextContent("High Risk");

  await user.click(pathCards[0]);

  expect(pathCards[0]).toHaveAttribute("aria-pressed", "true");
  expect(pathCards[1]).toHaveAttribute("aria-pressed", "false");

  await user.click(pathCards[1]);

  expect(pathCards[0]).toHaveAttribute("aria-pressed", "false");
  expect(pathCards[1]).toHaveAttribute("aria-pressed", "true");

  expect(screen.getByText("90")).toBeInTheDocument();
  expect(screen.getByText("65")).toBeInTheDocument();
});

it("preserves the original graph after an asset isolation simulation", async () => {
  const user = userEvent.setup();

  const originalNodes = [
    {
      id: "A01",
      name: "Internet",
      type: "External",
      ip: "0.0.0.0",
      criticality: "Low",
      exposed: "Yes",
      compromised: "No",
    },
    {
      id: "A06",
      name: "Customer-DB",
      type: "Database",
      ip: "10.0.0.6",
      criticality: "Critical",
      exposed: "No",
      compromised: "No",
    },
  ];

  const originalEdges = [
    {
      source: "A01",
      target: "A06",
      relationship: "CONNECTS",
      protocol: "TCP",
    },
  ];

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: originalNodes,
          edges: originalEdges,
        }),
      };
    }

    if (url.endsWith("/simulate-remediation")) {
      return {
        ok: true,
        json: async () => ({
          action_type: "isolate-asset",
          simulated_only: true,
          database_modified: false,
          before: {
            total_paths: 1,
            paths: [],
          },
          after: {
            total_paths: 0,
            paths: [],
          },
          paths_eliminated: 1,
          highest_risk_before: 90,
          highest_risk_after: 0,
          risk_score_reduction: 90,
          recommendations: [],
          scoring_note: "Simulation only. Original graph remains unchanged.",
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  // Confirm the original graph assets are displayed.
  // Confirm the original graph container remains mounted.
expect(document.querySelector(".graph-container")).toBeInTheDocument();

// Confirm the original graph data remains available in the asset selectors.
expect(screen.getAllByRole("option", { name: /Internet/i }).length).toBeGreaterThan(0);
expect(screen.getAllByRole("option", { name: /Customer-DB/i }).length).toBeGreaterThan(0);

  // Select Customer-DB for isolation.
  await user.selectOptions(
    screen.getByLabelText("Asset to isolate"),
    "A06"
  );

  // Run the simulation.
  await user.click(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  );

  // Verify that the simulation completed without modifying the database.
  expect(
    await screen.findByText("DATABASE UNCHANGED")
  ).toBeInTheDocument();

  // Verify the simulation request.
  const simulationCall = fetchMock.mock.calls.find(
    ([url]) => String(url).endsWith("/simulate-remediation")
  );

  expect(simulationCall).toBeDefined();

  const requestOptions = simulationCall![1] as RequestInit;

  expect(JSON.parse(requestOptions.body as string)).toEqual({
    action_type: "isolate-asset",
    target_id: "A06",
  });

  // Verify the original graph assets are still displayed.
  // Verify the graph remains mounted after simulation.
expect(document.querySelector(".graph-container")).toBeInTheDocument();

// Verify both original assets remain available in the asset selectors.
expect(screen.getAllByRole("option", { name: /Internet/i }).length).toBeGreaterThan(0);
expect(screen.getAllByRole("option", { name: /Customer-DB/i }).length).toBeGreaterThan(0);

  // Verify that the graph endpoint was called only once.
  const graphRequests = fetchMock.mock.calls.filter(
    ([url]) => String(url).endsWith("/graph")
  );

  expect(graphRequests).toHaveLength(1);

  // Verify the original graph data was not changed.
  expect(originalNodes).toHaveLength(2);
  expect(originalEdges).toHaveLength(1);
  expect(originalEdges[0]).toMatchObject({
    source: "A01",
    target: "A06",
    relationship: "CONNECTS",
  });
});


it("preserves the original graph after a connection removal simulation", async () => {
  const user = userEvent.setup();

  const originalNodes = [
    {
      id: "A01",
      name: "Internet",
      type: "External",
      ip: "0.0.0.0",
      criticality: "Low",
      exposed: "Yes",
      compromised: "No",
    },
    {
      id: "A06",
      name: "Customer-DB",
      type: "Database",
      ip: "10.0.0.6",
      criticality: "Critical",
      exposed: "No",
      compromised: "No",
    },
  ];

  const originalEdges = [
    {
      source: "A01",
      target: "A06",
      relationship: "CONNECTS",
      protocol: "TCP",
    },
  ];

  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    if (url.endsWith("/graph")) {
      return {
        ok: true,
        json: async () => ({
          nodes: originalNodes,
          edges: originalEdges,
        }),
      };
    }

    if (url.endsWith("/simulate-remediation")) {
      return {
        ok: true,
        json: async () => ({
          action_type: "remove-connection",
          simulated_only: true,
          database_modified: false,
          before: {
            total_paths: 1,
            paths: [],
          },
          after: {
            total_paths: 0,
            paths: [],
          },
          paths_eliminated: 1,
          highest_risk_before: 90,
          highest_risk_after: 0,
          risk_score_reduction: 90,
          recommendations: [],
          scoring_note: "Simulation only. Original graph remains unchanged.",
        }),
      };
    }

    throw new Error(`Unexpected API request: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  // Select connection removal.
  await user.selectOptions(
    screen.getByLabelText("Remediation action"),
    "remove-connection"
  );

  // Select the original connection.
  // Select the original connection to remove.
await user.selectOptions(
  screen.getByLabelText("Connection to remove"),
  "0"
);

  // Run the simulation.
  await user.click(
    screen.getByRole("button", {
      name: "Run Full-Graph Simulation",
    })
  );

  // Verify simulation completed without database modification.
  expect(
    await screen.findByText("DATABASE UNCHANGED")
  ).toBeInTheDocument();

  // Verify the simulation request.
  const simulationCall = fetchMock.mock.calls.find(
    ([url]) => String(url).endsWith("/simulate-remediation")
  );

  expect(simulationCall).toBeDefined();

  const requestOptions = simulationCall![1] as RequestInit;

  expect(JSON.parse(requestOptions.body as string)).toEqual({
    action_type: "remove-connection",
    source_id: "A01",
    destination_id: "A06",
    relationship: "CONNECTS",
  });

  // Verify the graph remains mounted.
  expect(document.querySelector(".graph-container")).toBeInTheDocument();

  // Verify original assets remain available.
  expect(screen.getAllByRole("option", { name: /Internet/i }).length).toBeGreaterThan(0);
  expect(screen.getAllByRole("option", { name: /Customer-DB/i }).length).toBeGreaterThan(0);

  // Verify the graph endpoint was called only once.
  const graphRequests = fetchMock.mock.calls.filter(
    ([url]) => String(url).endsWith("/graph")
  );

  expect(graphRequests).toHaveLength(1);

  // Verify the original connection data remains unchanged.
  expect(originalEdges).toHaveLength(1);
  expect(originalEdges[0]).toMatchObject({
    source: "A01",
    target: "A06",
    relationship: "CONNECTS",
  });
});

it("handles an empty graph response", async () => {
  vi.mocked(fetch).mockResolvedValueOnce({
    ok: true,
    json: async () => ({
      nodes: [],
      edges: [],
    }),
  } as Response);

  render(<App />);

  await waitFor(() => {
    expect(screen.getByText(/nexagraph/i)).toBeInTheDocument();
  });

  expect(document.querySelector(".graph-container")).toBeInTheDocument();
});


it("displays the correct dashboard statistics", async () => {
  vi.mocked(fetch).mockResolvedValueOnce({
    ok: true,
    json: async () => ({
      nodes: [
        {
          id: "A01",
          name: "Internet",
          type: "External",
          ip: "1.1.1.1",
          criticality: "Low",
          exposed: "Yes",
          compromised: "No",
        },
        {
          id: "A02",
          name: "Web Server",
          type: "Server",
          ip: "10.0.0.2",
          criticality: "Critical",
          exposed: "Yes",
          compromised: "Yes",
        },
        {
          id: "A03",
          name: "Employee PC",
          type: "Endpoint",
          ip: "10.0.0.3",
          criticality: "Medium",
          exposed: "No",
          compromised: "No",
        },
      ],
      edges: [
        {
          source: "A01",
          target: "A02",
          relationship: "CONNECTS",
          protocol: "TCP",
        },
        {
          source: "A02",
          target: "A03",
          relationship: "ACCESSES",
          protocol: "HTTPS",
        },
      ],
    }),
  } as Response);

  render(<App />);

  await waitFor(() => {
    expect(screen.getByText("Critical Assets")).toBeInTheDocument();
  });

  const getStatValue = (label: string) => {
  const statCards = document.querySelectorAll(".stat-card");

  const statCard = Array.from(statCards).find(
    (card) => card.querySelector("span")?.textContent?.trim() === label
  );

  return statCard?.querySelector("strong");
};
  expect(getStatValue("Assets")).toHaveTextContent("3");
  expect(getStatValue("Connections")).toHaveTextContent("2");
  expect(getStatValue("Critical Assets")).toHaveTextContent("1");
  expect(getStatValue("Compromised")).toHaveTextContent("1");
});

it("searches graph assets and highlights matching nodes", async () => {
  const user = userEvent.setup();

  render(<App />);

  await screen.findByText("SYSTEM ONLINE");

  const searchInput = screen.getByRole("searchbox", {
    name: "Search graph assets",
  });

  await user.type(searchInput, "Internet");

  await waitFor(() => {
    expect(mockCy.nodes).toHaveBeenCalled();
    expect(mockCy.animate).toHaveBeenCalledWith({
      fit: {
        eles: expect.anything(),
        padding: 70,
      },
      duration: 250,
    });
  });

  expect(searchInput).toHaveValue("Internet");
});

});
