const url = "http://127.0.0.1:8000/review-settings";

if (!window.fetch) {
  postData = postDataLikeIts1992
}

function postDataLikeIts1992() {
  const form = new URLSearchParams(new FormData(document.getElementById("review-capacity-form")));
  var http = new XMLHttpRequest();
  var params = '';
  for (var i=0; i<form.length; i++) {
    params = form[i] + '&=' + form[i];
  }
  http.open('POST', url, true);
  http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  http.onreadystatechange = function() {
    if (http.readyState == 4 && http.status == 201) {
      console.debug(http.responseText);
      update_view(JSON.parse(http.responseText)['detail'], "View updated");
    }
  }
  http.send(params);
}


async function update_view(content, msg, result_class) {
  var container = document.getElementById("message");
  container.innerHTML = msg;
  container.classList.add(result_class);

  // populate table
  var my_prefs = document.getElementById("my_prefs");
  var other_prefs = document.getElementById("other_prefs");
  let stuff = '';
  for (var i=0; i<content.length; i++) {
    const obj = content[i];
    console.debug(i + ", " + obj.username);
    const pto_start = new Date(obj.pto_date_start).toISOString().split('T')[0];
    const pto_end = new Date(obj.pto_date_end).toISOString().split('T')[0];
    const active = obj.active == true ? "checked=checked" : ''
    const publish = obj.publish_prefs == true ? "checked=checked" : ''
    stuff += `
<tr>
<td>
  <input name=id type=hidden value=${obj.id}>
  <input name=user_id type=hidden value=${obj.user_id}>
  <input name=username type=hidden value=${obj.username}><a href="https://github.com/rust-lang/rust/pulls/assigned/${obj.username}">${obj.username}</a>
</td>
<td><label><input name=active type=checkbox ${active}></label></td>
<td><input name=enable_max_assigned_prs type=checkbox checked=checked><input name=max_assigned_prs type=number value=${obj.max_assigned_prs}></td>
<td>
  <input name=pto_date_start type=date value=${pto_start}>&nbsp;
  <input name=pto_date_end type=date value=${pto_end}>
</td>
<td><input name=allow_ping_after_days type=number value=${obj.allow_ping_after_days}></td>
<td><label><input name=publish_prefs id="publish_prefs_${i}" type=checkbox ${publish}></label></td>
</tr>
`;

    if (i == 0) {
      my_prefs.insertAdjacentHTML('beforeend', stuff);
      stuff = '';
      console.debug("Added my prefs: " + obj.username);
    }
  }

  // Assumed the first row to be my profile
  // (ordered by the server)
  other_prefs.insertAdjacentHTML('beforeend', stuff);
  console.debug('Adding other prefs');

}

async function getData(user) {
  const response = await fetch(url, {
    method: "GET",
    headers: { "Role": user}
  });
  return response.json();
}

async function postData() {
  const form = new URLSearchParams(new FormData(document.getElementById("review-capacity-form")));
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": "Bearer USER",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form,
  });
  update_view(response.json(), "View updated", "success").await;
};

// load initial data
var isAdmin = false;
if (document.location.href.includes('admin') === true) {
  isAdmin = true;
}

var u = document.location.search.split('=')[1];
const user = u !== undefined ? u : 'pnkfelix';

getData(user).then((data) => {
  update_view(data, "View loaded", "success").await;
}).catch(error => {
  update_view({}, "Server is offline", "fail").await;
});
