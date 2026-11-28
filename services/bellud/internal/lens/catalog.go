package lens

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

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
	DefaultDepth = 3
	MaxDepth     = 6
	// MaxPathDepth bounds attack paths and network reach (Req 13.4).
	MaxPathDepth    = 6
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
	// Needs lists the collection categories an answer depends on.
	Needs []string `json:"-"`
	// Relations lists the relation types a category lens includes. Empty for
	// other lenses.
	Relations []string `json:"-"`
	// Overview is the Overview category of a category lens (Select category).
	Overview schema.OverviewCategory `json:"-"`
	// CollapseRules replaces rule nodes with group-to-peer edges by default;
	// the collapse_rules parameter overrides it.
	CollapseRules bool `json:"-"`
}

// Category ids used by Needs.
const (
	needNetwork  = "network"
	needIdentity = "identity"
	needData     = "data"
)

// Sentinel entries of Slice.MissingData.
const MissingNoExposedEntity = "no_internet_exposed_entity"

var collapseParam = Param{Name: "collapse_rules", Required: false}

var catalog = []Def{
	{
		ID: "code-to-cloud", Name: "Code to cloud", Layout: LayoutForce, Default: true,
		Description: "Repositories, packages, vulnerabilities, images and cloud resources, grouped by connection.",
		Kinds: []string{"github_org", "github_repo", "github_workflow", "github_alert", "package",
			"vulnerability", "aws_account", "aws_resource", "aws_sg_rule", "aws_cidr", "image"},
		Group: "connection", Select: SelectKinds, Params: []Param{collapseParam},
		Needs: []string{needNetwork},
	},
	{
		ID: "cloud", Name: "Cloud", Layout: LayoutForce,
		Description: "AWS accounts and resources, grouped by region.",
		Kinds:       []string{"aws_account", "aws_resource", "aws_sg_rule", "aws_cidr"},
		Group:       "region", Select: SelectKinds, Params: []Param{collapseParam},
		Needs: []string{needNetwork}, CollapseRules: true,
	},
	{
		ID: "blast-radius", Name: "Blast radius", Layout: LayoutRadial,
		Description: "Everything impacted by a failure of one entity.",
		Select:      SelectImpact,
		Params:      []Param{{Name: "entity", Required: true}, {Name: "depth", Required: false}, collapseParam},
		// identity and data stay needed while aws_can_access is not produced.
		Needs: []string{needNetwork, needIdentity, needData},
	},
	{
		ID: "attack-path", Name: "Attack path", Layout: LayoutChain,
		Description: "Connections from internet-exposed entities to a target entity or to every entity of a target type. Paths show connectivity, not a directed exploit route.",
		Select:      SelectAttackPaths,
		// One of target and target_type is required.
		Params: []Param{{Name: "target", Required: false}, {Name: "target_type", Required: false}, collapseParam},
		Needs:  []string{needNetwork},
	},
	{
		ID: "vulnerability-reachability", Name: "Vulnerability reachability", Layout: LayoutForce,
		Description: "Vulnerabilities whose impact reaches an internet-exposed entity.",
		Select:      SelectReachableVul,
		Params:      []Param{collapseParam},
		Needs:       []string{needNetwork},
	},
}

// ExposedNeeds are the needs of the exposed_resources question.
var ExposedNeeds = []string{needNetwork}

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
