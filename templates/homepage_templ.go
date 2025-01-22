// Code generated by templ - DO NOT EDIT.

// templ: version: v0.3.819
package templates

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

func Homepage() templ.Component {
	return templruntime.GeneratedTemplate(func(templ_7745c5c3_Input templruntime.GeneratedComponentInput) (templ_7745c5c3_Err error) {
		templ_7745c5c3_W, ctx := templ_7745c5c3_Input.Writer, templ_7745c5c3_Input.Context
		if templ_7745c5c3_CtxErr := ctx.Err(); templ_7745c5c3_CtxErr != nil {
			return templ_7745c5c3_CtxErr
		}
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templruntime.GetBuffer(templ_7745c5c3_W)
		if !templ_7745c5c3_IsBuffer {
			defer func() {
				templ_7745c5c3_BufErr := templruntime.ReleaseBuffer(templ_7745c5c3_Buffer)
				if templ_7745c5c3_Err == nil {
					templ_7745c5c3_Err = templ_7745c5c3_BufErr
				}
			}()
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<div class=\"flex flex-row\"><a href=\"/login\"><button class=\"bg-sky-400 p-2 rounded-lg\">Sign In</button></a></div><div class=\"flex\"><div id=\"side-nav\" class=\"flex-1\"><ul><li><a href=\"#this-site\">What is this site?</a></li><li><a href=\"#tech-stack\">What's the tech stack?</a></li></ul></div><div style=\"flex-grow: 7;\"><div id=\"this-site\">This site is a way for me to learn more about distributed systems. The site has two fundamental goals:<ul class=\"ml-4 list-disc\"><li>Be a useable social media site</li><li>Be highly performant, even under huge load</li></ul>The server is designed with high utilization in mind. My target for this service is to eventually reach 1 million concurrent users, automated by Apache <a href=\"https://jmeter.apache.org/\" class=\"decoration-blue-800 underline text-blue-800 visited:text-purple-600\">JMeter.</a></div><div id=\"tech-stack\">The tech stack for this site is as follows:<table><tr><th>Frontend</th><td>HTML, CSS (Tailwind), and <a href=\"vanilla-js.com\">Vanilla JS</a>.</td></tr><tr><th>Backend</th><td><a href=\"https://pkg.go.dev/net/http\">net/http</a> from Go's standard library, using various libraries for handling things like <a href=\"https://pkg.go.dev/github.com/golang-jwt/jwt/v5#section-readme\">JWT</a>, <a href=\"https://pkg.go.dev/github.com/justinas/alice@v1.2.0\">middleware</a>, and <a href=\"https://pkg.go.dev/github.com/couchbase/gocb/v2\">DB connections</a></td></tr><tr><th>Databases</th><td><a class=\"decoration-blue-800 underline text-blue-800 visited:text-purple-600\" href=\"https://www.postgres.org/\">Postgres</a> and <a class=\"decoration-blue-800 underline text-blue-800 visited:text-purple-600\" href=\"https://redis.io/\">Redis,</a> which need no introduction</td></tr></table></div></div></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

var _ = templruntime.GeneratedTemplate
