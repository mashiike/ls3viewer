<!doctype html>
<html charset="utf-8">
  <head>{{ $base := .BaseURL }}
    <title>{{ $bucket := .res.Name }}{{ $bucket }}/{{ .Prefix }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-iYQeCzEYFbKjA/T2uDLTpkwGzCiq6soy8tYaI1GyVh/UjpbCx/TYkiZhlZB6+fzT" crossorigin="anonymous">
  </head>
  <body>
    <div class="container">
    <div class="page-header">
      <h1>s3://{{ $bucket }}/{{ .ObjectKeyPrefix }}</h1>
    </div>
    <div class="list-group">
    {{if ne .Prefix "" }}
      <a href="../" class="list-group-item">
        <span class="glyphicon glyphicon-folder-close" aria-hidden="true"></span>
          ../
      </a>
    {{end}}
    {{range .res.CommonPrefixes}}
      <a href="{{ basename .Prefix }}/" class="list-group-item">
       <span class="glyphicon glyphicon-folder-close" aria-hidden="true"></span> {{ basename .Prefix }}/
      </a>
    {{end}}
    {{range .res.Contents}}
      {{if isDir .Key}}
      {{else}}
      <a href="{{$base}}/{{ .Key }}" class="list-group-item">
        <h4 class="list-group-item-heading">
          <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
          {{ basename .Key }}
        </h4>
        <p class="list-group-item-text">{{ bytes .Size }} | {{ .LastModified }}</p>
      </a>
      {{end}}
    {{end}}
    {{if .ContentBody }}
      <div class="card mt-3">
        <pre class="m-3"><code>{{ .ContentBody }}</code></pre>
      </div>
    {{end}}
    {{if .IsTrancated }}
      <ul class="pagination">
        <li class="page-item">
        <a class="page-link" href="{{ .NextPage }}">Next</a>
        </li>
      </ul>
    {{end}}
    </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-u1OknCvxWvY5kfmNBILK2hRnQC3Pr17a+RTT6rIHI7NnikvbZlHgTPOOmMi466C8" crossorigin="anonymous"></script>
  </body>
</html>
