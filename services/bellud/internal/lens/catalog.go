package lens

// DefaultLens is used when a request names no lens.
const DefaultLens = "code-to-cloud"

// Selection strategies.
const (
	SelectKinds        = "kinds"
	SelectImpact       = "impact"
	SelectAttackPaths  = "attack_paths"
	SelectReachableVul = "reachable_vulns"
)

// Layout names understood by the UI.
const (
	LayoutForce  = "force"
	LayoutRadial = "radial"
	LayoutChain  = "chain"
)

// Limits on lens parameters and traversal.
const (
	DefaultDepth    = 3
	MaxDepth        = 6
	AttackMaxDepth  = 8
	MaxExposed      = 50
	DefaultMaxNodes = 500
	DefaultMaxEdges = 1000
	// collectCap bounds the entities read for one slice before Budget runs.
	collectCap = 5000
)

// Param describes one request parameter of a lens.
type Param struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// Def is a lens definition.
type Def struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Layout      string   `json:"layout"`
	Default     bool     `json:"default"`
	Kinds       []string `json:"-"`
	Group       string   `json:"-"`
	Select      string   `json:"-"`
	Params      []Param  `json:"params"`
}

var catalog = []Def{
	{
		ID: "code-to-cloud", Name: "Code to cloud", Layout: LayoutForce, Default: true,
		Description: "Repositories, packages, vulnerabilities, images and cloud resources, grouped by connection.",
		Kinds: []string{"github_org", "github_repo", "github_workflow", "github_alert", "package",
			"vulnerability", "aws_account", "aws_resource", "image"},
		Group: "connection", Select: SelectKinds, Params: []Param{},
	},
	{
		ID: "cloud", Name: "Cloud", Layout: LayoutForce,
		Description: "AWS accounts and resources, grouped by region.",
		Kinds:       []string{"aws_account", "aws_resource"},
		Group:       "region", Select: SelectKinds, Params: []Param{},
	},
	{
		ID: "blast-radius", Name: "Blast radius", Layout: LayoutRadial,
		Description: "Everything impacted by a failure of one entity.",
		Select:      SelectImpact,
		Params:      []Param{{Name: "entity", Required: true}, {Name: "depth", Required: false}},
	},
	{
		ID: "attack-path", Name: "Attack path", Layout: LayoutChain,
		Description: "Connections from internet-exposed entities to a target. Paths show connectivity, not a directed exploit route.",
		Select:      SelectAttackPaths,
		Params:      []Param{{Name: "target", Required: true}},
	},
	{
		ID: "vulnerability-reachability", Name: "Vulnerability reachability", Layout: LayoutForce,
		Description: "Vulnerabilities whose impact reaches an internet-exposed entity.",
		Select:      SelectReachableVul,
		Params:      []Param{},
	},
}

// Catalog returns a copy of the lens definitions.
func Catalog() []Def {
	out := make([]Def, len(catalog))
	copy(out, catalog)
	return out
}

func lookup(id string) (Def, bool) {
	for _, d := range catalog {
		if d.ID == id {
			return d, true
		}
	}
	return Def{}, false
}
