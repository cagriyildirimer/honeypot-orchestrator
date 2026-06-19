const h = React.createElement;
import { App } from './components/App.js';

const rootNode = document.getElementById("app-root");
ReactDOM.createRoot(rootNode).render(h(App));
