<script>

  import { invoke } from '@tauri-apps/api/tauri'

  let url = ''
  let resource = ''

  async function greet() {
    console.log("clicked")
    resource = await invoke('showstr', { url })
    console.log("clicked")
  }

</script>


<div class="main">
  <input bind:value="{url}">
  <button on:click="{greet}">Search</button>
</div>
<div class="page">
  {@html resource}
</div>


<style>
    .main{
      display: grid;
    }
  input{
      grid-column-start: 1;
      grid-column-end: 5 ;
  }
  button{
      grid-column-start : 5;
      grid-column-end: 6;
  }
</style>